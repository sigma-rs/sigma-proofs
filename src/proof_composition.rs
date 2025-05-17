//! Sigma protocol composition: AND and OR constructions.
//!
//! This module provides combinators to compose two Sigma protocols
//! into a new protocol proving statements with logical AND or OR relations.
//!
//! # Overview
//! - `AndProtocol<P, Q>`: Proves both substatements (`P` and `Q`) simultaneously.
//! - `OrProtocol<P, Q>`: Proves knowledge of a witness for *one* substatement, without revealing which one (using simulation for the other).
//!
//! These constructions preserve zero-knowledge properties and follow standard Sigma protocol composition techniques.

use std::convert::TryInto;

use crate::{ProofError, SigmaProtocol, SigmaProtocolSimulator};

use ff::PrimeField;
use rand::{CryptoRng, Rng};

/// Logical AND composition of two Sigma protocols.
///
/// The prover must know witnesses for both subprotocols `P` and `Q`.
///
/// # Example
/// Proves that two independent statements hold simultaneously.
pub struct AndProtocol<P, Q>
where
    P: SigmaProtocol,
    Q: SigmaProtocol,
{
    protocol0: P,
    protocol1: Q,
}

impl<P, Q> AndProtocol<P, Q>
where
    P: SigmaProtocol,
    Q: SigmaProtocol,
{
    /// Create a new `AndProtocol` from two Sigma protocols.
    pub fn new(protocol0: P, protocol1: Q) -> Self {
        Self {
            protocol0,
            protocol1,
        }
    }
}

impl<P, Q> SigmaProtocol for AndProtocol<P, Q>
where
    P: SigmaProtocol,
    Q: SigmaProtocol<Challenge = P::Challenge>,
{
    type Commitment = (P::Commitment, Q::Commitment);
    type ProverState = (P::ProverState, Q::ProverState);
    type Response = (P::Response, Q::Response);
    type Witness = (P::Witness, Q::Witness);
    type Challenge = P::Challenge;

    fn prover_commit(
        &self,
        witnesses: &Self::Witness,
        rng: &mut (impl Rng + CryptoRng),
    ) -> (Self::Commitment, Self::ProverState) {
        let (commitment0, pr_st0) = self.protocol0.prover_commit(&witnesses.0, rng);
        let (commitment1, pr_st1) = self.protocol1.prover_commit(&witnesses.1, rng);

        ((commitment0, commitment1), (pr_st0, pr_st1))
    }

    fn prover_response(
        &self,
        state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Self::Response {
        // Compute responses
        let response0 = self.protocol0.prover_response(state.0, challenge);
        let response1 = self.protocol1.prover_response(state.1, challenge);

        (response0, response1)
    }

    fn verifier(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<(), ProofError> {
        let verif0 = self
            .protocol0
            .verifier(&commitment.0, challenge, &response.0);
        let verif1 = self
            .protocol1
            .verifier(&commitment.1, challenge, &response.1);

        match (verif0, verif1) {
            (Ok(()), Ok(())) => Ok(()),
            _ => Err(ProofError::VerificationFailure),
        }
    }

    fn serialize_batchable(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<Vec<u8>, ProofError> {
        let ser0 = self
            .protocol0
            .serialize_batchable(&commitment.0, challenge, &response.0)?;
        let ser1 = self
            .protocol1
            .serialize_batchable(&commitment.1, challenge, &response.1)?;
        let len0 = ser0.len() as u32;

        let mut out = ser0;
        out.extend(ser1);
        out.extend(&len0.to_le_bytes()); // append length hint as trailer
        Ok(out)
    }

    fn deserialize_batchable(&self, data: &[u8]) -> Result<(Self::Commitment, Self::Response), ProofError> {
        if data.len() < 4 {
            return Err(ProofError::GroupSerializationFailure); // not enough bytes to contain the length suffix
        }

        // Split off the last 4 bytes as the trailer
        let (proof_data, len_bytes) = data.split_at(data.len() - 4);
        let len0 = u32::from_le_bytes(len_bytes.try_into().unwrap()) as usize;

        if proof_data.len() < len0 {
            return Err(ProofError::GroupSerializationFailure); // length hint exceeds available bytes
        }

        let (ser0, ser1) = proof_data.split_at(len0);

        let (commitment0, response0) = self.protocol0.deserialize_batchable(ser0)?;
        let (commitment1, response1) = self.protocol1.deserialize_batchable(ser1)?;

        Ok(((commitment0, commitment1), (response0, response1)))
    }
}

/// Logical OR composition of two Sigma protocols.
///
/// The prover knows a witness for **one** subprotocol `P` *or* `Q`,
/// but does not reveal which. This uses simulation to hide the other statement.
pub struct OrProtocol<P, Q>
where
    P: SigmaProtocol,
    Q: SigmaProtocol,
{
    protocol0: P,
    protocol1: Q,
}

impl<P, Q> OrProtocol<P, Q>
where
    P: SigmaProtocol,
    Q: SigmaProtocol,
{
    /// Create a new `OrProtocol` from two Sigma protocols.
    pub fn new(protocol0: P, protocol1: Q) -> Self {
        Self {
            protocol0,
            protocol1,
        }
    }
}

/// Enum to wrap either the left or right variant in an OR proof.
pub enum OrEnum<L, R> {
    Left(L),
    Right(R),
}

/// Internal state for a simulated transcription in an OR proof.
pub struct OrState<P: SigmaProtocol>(P::Challenge, P::Response);

/// Enum to describe which side (left or right) is simulated in an OR proof.
pub enum OrTranscription<P, Q>
where
    P: SigmaProtocol,
    Q: SigmaProtocol,
{
    Left(OrState<P>),
    Right(OrState<Q>),
}

impl<P, Q, C> SigmaProtocol for OrProtocol<P, Q>
where
    C: PrimeField,
    P: SigmaProtocol<Challenge = C> + SigmaProtocolSimulator,
    Q: SigmaProtocol<Challenge = C> + SigmaProtocolSimulator,
    P::Response: Clone,
    Q::Response: Clone,
{
    type Commitment = (P::Commitment, Q::Commitment);
    type ProverState = (
        usize,
        OrEnum<P::ProverState, Q::ProverState>,
        OrTranscription<P, Q>,
    ); // ProverState = (real index, real prover state = (r, &real witness), fake transcription)
    type Response = (P::Challenge, P::Response, Q::Response);
    type Witness = (usize, OrEnum<P::Witness, Q::Witness>); // Index of the real witness, and Enum to wrap the real witness
    type Challenge = P::Challenge;

    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut (impl Rng + CryptoRng),
    ) -> (Self::Commitment, Self::ProverState) {
        // real index and real witness (wrapped)
        let (r_index, r_witness_w) = witness;
        match r_witness_w {
            OrEnum::Left(ref r_witness) => {
                let f_trnsc = self.protocol1.simulate_transcription(rng);
                let ST = OrState(f_trnsc.1, f_trnsc.2);
                let (commit, r_pr_st) = self.protocol0.prover_commit(r_witness, rng);
                (
                    (commit, f_trnsc.0),
                    (*r_index, OrEnum::Left(r_pr_st), OrTranscription::Right(ST)),
                )
            }
            OrEnum::Right(ref r_witness) => {
                let f_trnsc = self.protocol0.simulate_transcription(rng);
                let ST = OrState(f_trnsc.1, f_trnsc.2);
                let (commit, r_pr_st) = self.protocol1.prover_commit(r_witness, rng);
                (
                    (f_trnsc.0, commit),
                    (*r_index, OrEnum::Right(r_pr_st), OrTranscription::Left(ST)),
                )
            }
        }
    }

    fn prover_response(
        &self,
        state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Self::Response {
        // let state = (real index, real prover state, fakee transcription)
        let (_, r_pr_st, f_trnsc) = state;

        // Compute the real challenge
        let r_challenge = match &f_trnsc {
            OrTranscription::Left(OrState(ch, _)) => *challenge - ch,
            OrTranscription::Right(OrState(ch, _)) => *challenge - ch,
        };

        match (r_pr_st, f_trnsc) {
            (OrEnum::Left(r_prover_state), OrTranscription::Right(OrState(_, f_response))) => {
                let r_response = self.protocol0.prover_response(r_prover_state, &r_challenge);
                (r_challenge, r_response, f_response.clone())
            }
            (OrEnum::Right(r_prover_state), OrTranscription::Left(OrState(f_ch, f_response))) => {
                let r_response = self.protocol1.prover_response(r_prover_state, &r_challenge);
                (f_ch, f_response.clone(), r_response)
            }
            _ => panic!("Incoherence between real prover state and fake transcription"),
        }
    }

    fn verifier(
        &self,
        commitments: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<(), ProofError> {
        let cond0 = self
            .protocol0
            .verifier(&commitments.0, &response.0, &response.1);

        let challenge1 = *challenge - response.0;
        let cond1 = self
            .protocol1
            .verifier(&commitments.1, &challenge1, &response.2);

        match (cond0, cond1) {
            (Ok(()), Ok(())) => Ok(()),
            _ => Err(ProofError::VerificationFailure),
        }
    }

    fn serialize_batchable(
        &self,
        commitment: &Self::Commitment,
        challenge: &Self::Challenge,
        response: &Self::Response,
    ) -> Result<Vec<u8>, ProofError> {
        let (ch0, resp0, resp1) = response;
        let ch1 = *challenge - *ch0;

        let ser0 = self
            .protocol0
            .serialize_batchable(&commitment.0, ch0, resp0)?;
        let ser1 = self
            .protocol1
            .serialize_batchable(&commitment.1, &ch1, resp1)?;

        let mut out = ser0.clone();
        out.extend(&ser1);
        out.extend(ch0.to_repr().as_ref()); // serialize ch0
        out.extend(&(ser0.len() as u32).to_le_bytes()); // append len0 (length of ser0)

        Ok(out)
    }

    fn deserialize_batchable(&self, data: &[u8]) -> Result<(Self::Commitment, Self::Response), ProofError> {
        // The challenge is appended as `Challenge::Repr`, which must be a fixed size
        let repr_len = <C as PrimeField>::Repr::default().as_ref().len();
        if data.len() < repr_len + 4 {
            return Err(ProofError::GroupSerializationFailure);
        }

        let len0_bytes = &data[data.len() - 4..];
        let ch0_bytes = &data[data.len() - 4 - repr_len..data.len() - 4];
        let proof_data = &data[..data.len() - repr_len - 4];

        let len0 = u32::from_le_bytes(len0_bytes.try_into().unwrap()) as usize;
        if proof_data.len() < len0 {
            return Err(ProofError::GroupSerializationFailure);
        }

        let mut repr = <C as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(ch0_bytes);

        let result_ctoption = C::from_repr(repr);
        if (!result_ctoption.is_some()).into() {
            return Err(ProofError::GroupSerializationFailure);
        }
        let ch0 = result_ctoption.unwrap();

        let (proof0_bytes, proof1_bytes) = proof_data.split_at(len0);
        let (commitment0, response0) = self.protocol0.deserialize_batchable(proof0_bytes)?;
        let (commitment1, response1) = self.protocol1.deserialize_batchable(proof1_bytes)?;

        Ok(((commitment0, commitment1), (ch0, response0, response1)))
    }
}
