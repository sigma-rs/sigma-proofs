use sha3::{Shake128, digest::{Update, ExtendableOutput, XofReader}};
use group::{Group, GroupEncoding};
use ff::PrimeField;

use crate::toolbox::sigma::transcript::r#trait::TranscriptCodec;

pub struct KeccakTranscript<G: Group> {
    hasher: Shake128,
    _marker: core::marker::PhantomData<G>,
}

impl<G> TranscriptCodec<G> for KeccakTranscript<G>
where
    G: Group + GroupEncoding,
    G::Scalar: PrimeField,
{
    fn new(domain_sep: &[u8]) -> Self {
        let mut hasher = Shake128::default();
        hasher.update(domain_sep);
        Self { hasher, _marker: Default::default() }
    }

    fn prover_message(mut self, elems: &[G]) -> Self {
        for elem in elems {
            self.hasher.update(elem.to_bytes().as_ref());
        }
        self
    }

    fn verifier_challenge(&mut self) -> G::Scalar {
        let mut reader = self.hasher.clone().finalize_xof();
        let mut buf = [0u8; 64];
        reader.read(&mut buf);
    
        let challenge_len = <<G as Group>::Scalar as PrimeField>::Repr::default().as_ref().len();
        let mut repr = <<G as Group>::Scalar as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(&buf[..challenge_len]);
    
        G::Scalar::from_repr(repr).unwrap()
    }
}