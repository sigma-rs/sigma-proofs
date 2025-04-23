use group::Group;

/// A trait for domain-separated transcript hashing for Sigma protocols.
/// This mirrors Sage's ByteSchnorrCodec behavior.
pub trait TranscriptCodec<G: Group> {
    fn new(domain_sep: &[u8]) -> Self;

    /// Absorb a list of group elements (e.g., commitments).
    fn prover_message(&mut self, elems: &[G]) -> &mut Self
    where
        Self: Sized;

    /// Produce a scalar challenge from the transcript.
    fn verifier_challenge(&mut self) -> G::Scalar;
}