//! Example: OR-proofs.
//!
//! This example demonstrates disjunctive proofs: proving you satisfy ONE of multiple conditions
//! without revealing which. For instance, proving you own either address A or address B,
//! without revealing which address is yours.
//!
//! The two statements are expressed over a group \mathbb{G} of prime order $p$, where the discrete logarithm problem is hard.
//! In this group, the prover wishes to convince a verifier that it knows a secret scalar $x \in \mathbb{Z}_p$
//! such that *at least one* of the following statements holds:
//!
//! 1. **Discrete Logarithm (DLog):**
//!
//!     $$X_1 = x_1 \cdot G$$
//!
//! 2. **Discrete Log Equality (DLEQ):**
//!
//!     $$X_2 = x_2 \cdot G \quad \text{and} \quad Y_2 = x_2 \cdot H$$
//!
//! For these statements, the elements $G, H, X_1, X_2, Y_2$ are all publicly available to any verifier.
//!
//! In our specific case, we will consider that the prover only knows a witness for the second statement. However,
//! he will prove *the disjunction* of the two statements, using an OR-composition of Sigma protocols.
//! This proof reveals nothing about *which* statement and witness has been used by the prover.
//!
//! ---
//!
//! In `sigma-rs`, this is implemented using three core abstractions:
//!
//! 1. [`LinearRelation`] — describes the *morphism* (algebraic relation) between secret scalars and group elements.
//!    This forms the mathematical statement of the protocol. In our case, $X_1 = x \cdot G \cup X_2 = x_2 \cdot G \quad \text{and} \quad Y_2 = x_2 \cdot H$
//!
//! 2. [`Protocol`] — defines the interactive Sigma protocol for the given morphism.
//!    This handles the commit-challenge-response structure of the protocol, following the standard Sigma protocol flow:
//!     - P → V: commit
//!     - V → P: challenge
//!     - P → V: response
//!
//! 3. [`NISigmaProtocol`] — wraps the interactive protocol using the Fiat-Shamir transformation,
//!    converting it to a *non-interactive zero-knowledge proof* (NIZK) by deriving the challenge
//!    from a transcript hash using a [`Codec`] (here, [`ShakeCodec`]).
//!
//! The resulting proof is non-interactive, zero-knowledge, and secure in the random oracle model.
//!
//! ---
//!
//! This example uses the Ristretto group from `curve25519-dalek`, a prime-order group designed for security and
//! compatibility with zero-knowledge protocols.
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use group::{Group, GroupEncoding};
use rand::rngs::OsRng;
use sigma_rs::{
    LinearRelation,
    codec::ShakeCodec,
    composition::{Protocol, ProtocolWitness},
    fiat_shamir::NISigmaProtocol,
};

type G = RistrettoPoint;

/// Construct the relation `X = x·G` and return it along with the witness `x`.
/// - `x` is a secret scalar in $\mathbb{Z}_p$.
/// - `G`, `X` are elements in a prime-order group $\mathbb{G}$.
#[allow(non_snake_case)]
pub fn discrete_logarithm<G: Group + GroupEncoding>(
    x: G::Scalar,
) -> (LinearRelation<G>, Vec<G::Scalar>) {
    let mut morphism = LinearRelation::<G>::new();

    // Allocate symbolic variables for our relation
    let var_x = morphism.allocate_scalar();
    let var_G = morphism.allocate_element();

    // Define the constraint: `X = x * G`
    let var_X = morphism.allocate_eq(var_x * var_G);

    // Assign concrete values
    morphism.set_element(var_G, G::generator());
    morphism.compute_image(&[x]).unwrap();

    // Verify: X = x * G
    let X = morphism.linear_map.group_elements.get(var_X).unwrap();
    assert_eq!(X, G::generator() * x);

    (morphism, vec![x])
}

/// Construct the relation `(X = x·G, Y = x·H)` and return it along with the witness `x`.
/// This represents a DLEQ (discrete log equality) statement between two basepoints.
/// - `x` is a secret scalar in $\mathbb{Z}_p$.
/// - `G`, `H`, `X`, `Y` are elements in a prime-order group $\mathbb{G}$. `G` in particular is a fixed generator.
#[allow(non_snake_case)]
pub fn dleq<G: Group + GroupEncoding>(x: G::Scalar, H: G) -> (LinearRelation<G>, Vec<G::Scalar>) {
    let mut morphism = LinearRelation::<G>::new();

    // Allocate symbolic variables
    let var_x = morphism.allocate_scalar();
    let [var_G, var_H] = morphism.allocate_elements();

    // Define the constraints: X = x * G, Y = x * H
    let _var_X = morphism.allocate_eq(var_x * var_G);
    let _var_Y = morphism.allocate_eq(var_x * var_H);

    // Assign concrete values
    morphism.set_elements([(var_G, G::generator()), (var_H, H)]);
    morphism.compute_image(&[x]).unwrap();

    // Verify: X = x * G and Y = x * H
    let X = morphism.linear_map.group_elements.get(_var_X).unwrap();
    let Y = morphism.linear_map.group_elements.get(_var_Y).unwrap();
    assert_eq!(X, G::generator() * x);
    assert_eq!(Y, H * x);

    (morphism, vec![x])
}

#[allow(non_snake_case)]
fn main() {
    let mut rng = OsRng;

    // Setup: Create two relations
    // Relation 1: DLog (we don't know a witness for this)
    let _x1 = Scalar::random(&mut rng);
    let (rel1, _) = discrete_logarithm::<G>(_x1);

    // Relation 2: DLEQ (we DO know the witness)
    let x2 = Scalar::random(&mut rng);
    let H = G::random(&mut rng);
    let (rel2, witness2) = dleq::<G>(x2, H);

    // Compose into OR protocol

    // Wrap each relation into a Sigma protocol
    let proto1 = Protocol::from(rel1);
    let proto2 = Protocol::from(rel2);

    // Compose both protocols using logical OR
    let composed = Protocol::Or(vec![proto1, proto2]);

    // Declare the known witness for the second protocol (index = 1)
    let witness = ProtocolWitness::Or(1, vec![ProtocolWitness::Simple(witness2)]);

    // Generate and verify proof
    // Make it non-interactive via Fiat-Shamir
    let nizk = NISigmaProtocol::<_, ShakeCodec<G>>::new(b"or_proof_example", composed);

    // Generate proof (proving we know witness for statement 2, but not revealing which)
    let proof = nizk
        .prove_batchable(&witness, &mut rng)
        .expect("Proof generation should succeed");

    // Verify the proof
    let verified = nizk.verify_batchable(&proof).is_ok();
    println!("OR-proof verified: {verified}");
}
