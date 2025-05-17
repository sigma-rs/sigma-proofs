//! Proof Builder for Sigma Protocols
//!
//! This module defines the [`ProofBuilder`] struct, a high-level utility that simplifies
//! the construction and interaction with zero-knowledge proofs based on Sigma protocols.
//!
//! It abstracts over the underlying Schnorr protocol, Fiat-Shamir transformation,
//! and serialization concerns, making it easier to create proofs from linear
//! relations over cryptographic groups.
//!
//! ## Features
//! - Allocates scalar and point variables for constructing group equations
//! - Appends equations representing statements to be proven
//! - Supports element assignment to statement variables
//! - Offers one-shot `prove` and `verify` methods

use group::Group;
use rand::{CryptoRng, RngCore};

use crate::{
    codec::ShakeCodec, serialisation::GroupSerialisation, GroupMorphismPreimage, NISigmaProtocol,
    PointVar, ProofError, ScalarVar, SchnorrProtocol,
};

/// A builder that helps construct Sigma proofs for linear group relations.
///
/// This struct wraps a [`SchnorrProtocol`] over a [`GroupMorphismPreimage`] and applies
/// the Fiat-Shamir transform via [`NISigmaProtocol`]. It provides a user-friendly API
/// for allocating variables, defining statements, and generating proofs.
///
/// # Type Parameters
/// - `G`: A group that implements both [`Group`] and [`GroupSerialisation`], such as `RistrettoPoint` or `G1Projective`.
pub struct ProofBuilder<G>
where
    G: Group + GroupSerialisation,
{
    /// The underlying Sigma protocol instance with Fiat-Shamir transformation applied.
    pub protocol: NISigmaProtocol<SchnorrProtocol<G>, ShakeCodec<G>, G>,
}

impl<G> ProofBuilder<G>
where
    G: Group + GroupSerialisation,
    ShakeCodec<G>: Clone,
{
    /// Creates a new proof builder with a Schnorr protocol instance using the given domain separator.
    pub fn new(domain_sep: &[u8]) -> Self {
        let schnorr_proof = SchnorrProtocol(GroupMorphismPreimage::<G>::new());
        let protocol =
            NISigmaProtocol::<SchnorrProtocol<G>, ShakeCodec<G>, G>::new(domain_sep, schnorr_proof);
        Self { protocol }
    }

    /// Adds a new equation to the proof statement of the form:
    /// `lhs = Σ (scalar_i * point_i)`
    ///
    /// # Parameters
    /// - `lhs`: The variable representing the left-hand group element
    /// - `rhs`: A list of (scalar variable, point variable) tuples for the linear combination
    pub fn append_equation(&mut self, lhs: PointVar, rhs: &[(ScalarVar, PointVar)]) {
        self.protocol.sigmap.0.append_equation(lhs, rhs);
    }

    /// Allocates `n` scalar variables for use in the proof.
    ///
    /// Returns a vector of `ScalarVar` indices.
    pub fn allocate_scalars(&mut self, n: usize) -> Vec<ScalarVar> {
        self.protocol.sigmap.0.allocate_scalars(n)
    }

    /// Allocates `n` point variables (group elements) for use in the proof.
    ///
    /// Returns a vector of `PointVar` indices.
    pub fn allocate_elements(&mut self, n: usize) -> Vec<PointVar> {
        self.protocol.sigmap.0.allocate_elements(n)
    }

    /// Assigns specific group elements to point variables (indices).
    ///
    /// # Parameters
    /// - `elements`: A list of `(PointVar, GroupElement)` pairs
    pub fn set_elements(&mut self, elements: &[(PointVar, G)]) {
        self.protocol.sigmap.0.set_elements(elements);
    }

    /// Returns the expected group element results (`lhs`) of the current equations.
    ///
    /// This corresponds to the image values of the equations under the morphism.
    pub fn image(&self) -> Vec<G> {
        self.protocol.sigmap.0.image()
    }

    /// Generates a non-interactive zero-knowledge proof for the current statement using the given witness.
    ///
    /// # Parameters
    /// - `witness`: A list of scalars (one per allocated scalar variable)
    /// - `rng`: A random number generator
    ///
    /// # Returns
    /// A serialized proof as a vector of bytes in batchable ('commitment', 'response') format.
    pub fn prove(
        &mut self,
        witness: &[<G as Group>::Scalar],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Vec<u8> {
        let witness_tmp = witness.to_vec();
        self.protocol.prove_batchable(&witness_tmp, rng)
    }

    /// Verifies a serialized proof against the current statement.
    ///
    /// # Parameters
    /// - `proof`: A byte slice containing the serialized proof
    ///
    /// # Returns
    /// `Ok(())` if the proof is valid, or a [`ProofError`] if verification fails.
    pub fn verify(&mut self, proof: &[u8]) -> Result<(), ProofError> {
        self.protocol.verify_batchable(proof)
    }

    pub fn prove_compact(
        &mut self,
        witness: &[<G as Group>::Scalar],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Vec<u8> {
        let witness_tmp = witness.to_vec();
        self.protocol.prove_compact(&witness_tmp, rng)
    }

    pub fn verify_compact(&mut self, proof: &[u8]) -> Result<(), ProofError> {
        self.protocol.verify_compact(proof)
    }
}
