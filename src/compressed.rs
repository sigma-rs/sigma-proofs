//! Compressed Σ-protocols: logarithmic-size arguments for [`Instance`] statements.
//!
//! The proof size is `1 + 2·⌈log2(n)⌉` group elements and one scalar (Attema and Cramer, CRYPTO 2020).
//! This folding is the same one Bulletproofs uses.
//!
//! ```
//! use curve25519_dalek::{RistrettoPoint as G, Scalar};
//! use group::Group;
//! use sigma_proofs::compressed::Compressed;
//! use sigma_proofs::LinearRelation;
//! use spongefish::{derive_session_id, Narg, StdHash};
//!
//! let witness = vec![Scalar::from(3u64), Scalar::from(5u64)];
//! let mut relation = LinearRelation::<G>::new();
//! let [x, y] = relation.allocate_scalars();
//! let h = relation.allocate_element_with(G::generator() * Scalar::from(7u64));
//! relation.allocate_eq(x * relation.generator() + y * h);
//! let instance = relation.compile_with_witness(&witness).unwrap();
//!
//! let session_id = derive_session_id::<StdHash>(b"my-application compressed");
//! let (narg_string, ()) =
//!     Narg::prove::<Compressed<G>>(&session_id, &instance, &witness).unwrap();
//! Narg::verify::<Compressed<G>>(&session_id, &instance, &narg_string).unwrap();
//! ```
//!
//! [`Argument`]: spongefish::Argument
//! [`Transcript`]: spongefish::Transcript
//! [`FiatShamir`]: spongefish::FiatShamir
//! [`FiatShamir::prove`]: spongefish::FiatShamir::prove
//! [`FiatShamir::verify`]: spongefish::FiatShamir::verify

// Runs on NARG strings an attacker chose; see `docs/threat-model.md` §2.1.
#![deny(clippy::indexing_slicing, clippy::expect_used, clippy::unwrap_used)]

use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use ff::Field;
use group::prime::PrimeGroup;
use spongefish::{
    Argument, ByteArray, Decoding, Encoding, NargDeserialize, NargReader, Transcript,
    VerificationError, VerificationResult, Witness,
};

use crate::codec::{deserialize_elements, deserialize_scalars, GroupCodec, ScalarCodec};
use crate::linear_relation::Instance;
use crate::msm::MultiScalarMul;

/// The number of the uniform bytes squeeze to produce a verifier challenge.
const UNIFORM_BYTES: usize = 64;

/// A verifier challenge message.
///
/// Wraps around the field type to implement [`Encoding`].
#[derive(Clone, Copy, Debug)]
struct Challenge<F>(F);

/// A round's group elements: `[T]`, the commitment of the blinding round, or
/// `[A, B]`, the cross terms of a fold round.
#[derive(Clone, Copy, Debug)]
struct RoundMessage<G, const N: usize>([G; N]);

impl<F: ScalarCodec> Decoding<[u8]> for Challenge<F> {
    type Repr = ByteArray<UNIFORM_BYTES>;

    fn decode(buf: Self::Repr) -> Self {
        Self(F::from_uniform_bytes(AsRef::<[u8; UNIFORM_BYTES]>::as_ref(
            &buf,
        )))
    }
}

impl<G: GroupCodec, const N: usize> Encoding<[u8]> for RoundMessage<G, N> {
    fn encode(&self) -> impl AsRef<[u8]> {
        let mut out = Vec::new();
        G::serialize_elements_allowing_identity(&self.0, &mut out);
        out
    }
}

impl<G: GroupCodec, const N: usize> NargDeserialize for RoundMessage<G, N> {
    fn deserialize_from_narg(reader: &mut NargReader<'_>) -> VerificationResult<Self> {
        let elements = deserialize_elements::<G>(reader, N)?;
        match <[G; N]>::try_from(elements) {
            Ok(elements) => Ok(Self(elements)),
            Err(_) => Err(VerificationError),
        }
    }
}

/// The last round's single scalar: the fully folded response.
#[derive(Clone, Copy, Debug)]
struct Opening<F>(F);

impl<F: ScalarCodec> Encoding<[u8]> for Opening<F> {
    fn encode(&self) -> impl AsRef<[u8]> {
        let mut out = Vec::new();
        self.0.serialize_scalar(&mut out);
        out
    }
}

impl<F: ScalarCodec> NargDeserialize for Opening<F> {
    fn deserialize_from_narg(reader: &mut NargReader<'_>) -> VerificationResult<Self> {
        let scalars = deserialize_scalars::<F>(reader, 1)?;
        match scalars.first() {
            Some(&scalar) => Ok(Self(scalar)),
            None => Err(VerificationError),
        }
    }
}

/// A statement reduced to one inner-product `image = <witness, generators>`.
struct SquashedInstance<G: PrimeGroup> {
    generators: Vec<G>,
    image: G,
}

/// `powers(x, n) = [1, x, x^2, ..., x^(n-1)]`.
fn powers<F: Field>(x: F, n: usize) -> Vec<F> {
    let mut out = Vec::with_capacity(n);
    let mut acc = F::ONE;
    for _ in 0..n {
        out.push(acc);
        acc *= x;
    }
    out
}

impl<G> Instance<G>
where
    G: PrimeGroup + MultiScalarMul + GroupCodec,
    G::Scalar: ScalarCodec,
{
    /// Collapses the instance's `m` equations (rows) into one
    /// equation `image = <witness, generators>`.
    fn squash(&self, challenge: G::Scalar) -> SquashedInstance<G> {
        let weights = powers(challenge, self.num_equations());
        let image = G::msm_vartime(&weights, self.image());

        // Keep one identity generator for the valid empty instance.
        let width = self.num_scalars().max(1);
        let mut generators = vec![G::identity(); width];

        for (row, equation) in self.equations().iter().enumerate() {
            // `row` indexes `weights`, which was built with one entry per
            // equation; `scalar_index` and `element_index` are bounded by
            // `num_scalars()` and `num_elements()` on a validated instance
            // (checks 5 and 6), and `generators` is `num_scalars()` long
            // wherever there is a term to index it with.
            #[allow(clippy::indexing_slicing)]
            for &(scalar_index, element_index, coeff) in &equation.terms {
                let base = *self
                    .element(element_index as usize)
                    .expect("validated element index");
                generators[scalar_index as usize] += base * (coeff * weights[row]);
            }
        }

        SquashedInstance { generators, image }
    }
}

/// The prover's round message.
///
/// Computes the cross terms of the halved inner product `[A, B]`.
fn cross_terms<G>(response: &[G::Scalar], generators: &[G], half: usize) -> [G; 2]
where
    G: PrimeGroup + MultiScalarMul,
{
    let (z_left, z_right) = response.split_at(half);
    let (g_left, g_right) = generators.split_at(half);
    let (z_paired, _) = z_left.split_at(z_right.len());
    let (g_paired, _) = g_left.split_at(g_right.len());
    [G::msm(z_paired, g_right), G::msm(z_right, g_paired)]
}

/// Computes `left + x * right` for scalars.
fn fold_scalars<F: Field>(values: &mut Vec<F>, half: usize, x: F) {
    let (left, right) = values.split_at_mut(half);
    for (l, r) in core::iter::zip(left, right) {
        *l += *r * x;
    }
    values.truncate(half);
}

/// Computes `x * left + right` for group elements.
fn fold_generators<G: PrimeGroup>(values: &mut Vec<G>, half: usize, x: G::Scalar) {
    let (left, right) = values.split_at_mut(half);
    let (paired, unpaired) = left.split_at_mut(right.len());
    for (l, r) in core::iter::zip(paired, right) {
        *l = *l * x + *r;
    }
    for l in unpaired {
        *l *= x;
    }
    values.truncate(half);
}

/// The compressed argument for [`Instance`], as a
/// [`spongefish::Argument`].
pub struct Compressed<G>(PhantomData<G>);

impl<G> Argument for Compressed<G>
where
    G: PrimeGroup + MultiScalarMul + GroupCodec,
    G::Scalar: ScalarCodec,
{
    type Instance = Instance<G>;
    type Witness = Vec<G::Scalar>;
    type Output = ();

    fn run<T: Transcript>(
        transcript: &mut T,
        instance: &Instance<G>,
        witness: Witness<&Self::Witness>,
    ) -> VerificationResult<()> {
        // Squash first into ann inner-product.
        let Challenge(squash) = transcript.verifier_message::<Challenge<G::Scalar>>();
        let mut statement = instance.squash(squash);

        // Sample a the masking vector.
        let width = statement.generators.len();
        let nonces = transcript
            .sample_vec::<Challenge<G::Scalar>>(width)
            .map(|nonces| {
                nonces
                    .into_iter()
                    .map(|Challenge(nonce)| nonce)
                    .collect::<Vec<_>>()
            });
        let commitment = nonces
            .as_ref()
            .map(|nonces| RoundMessage([G::msm(nonces, &statement.generators)]));
        let RoundMessage([commitment]) = transcript.prover_message(commitment)?;
        let Challenge(challenge) = transcript.verifier_message::<Challenge<G::Scalar>>();

        // The response `z = nonces + challenge * witness`
        // is proven with a log-round argument.
        let mut response = nonces.zip(witness).map(|(mut response, witness)| {
            for (z, w) in core::iter::zip(&mut response, witness) {
                *z += *w * challenge;
            }
            response
        });
        statement.image = commitment + statement.image * challenge;
        while statement.generators.len() > 1 {
            let half = statement.generators.len().div_ceil(2);

            let message = response
                .as_ref()
                .map(|z| RoundMessage(cross_terms::<G>(z, &statement.generators, half)));
            let RoundMessage([a, b]) = transcript.prover_message(message)?;

            let Challenge(x) = transcript.verifier_message::<Challenge<G::Scalar>>();

            response = response.map(|mut z| {
                fold_scalars(&mut z, half, x);
                z
            });
            fold_generators(&mut statement.generators, half, x);
            statement.image = a + statement.image * x + b * x.square();
        }

        // One generator left, so the folded response is one scalar and the
        // statement is `image == generator * opening`.
        let opening =
            response.map(|z| Opening(z.first().copied().unwrap_or(<G::Scalar as Field>::ZERO)));
        let Opening(opening) = transcript.prover_message(opening)?;

        let generator = statement.generators.first().copied();
        transcript.check(|| match generator {
            Some(generator) => generator * opening == statement.image,
            None => false,
        })
    }
}
