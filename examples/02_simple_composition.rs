//! Example: OR-proof (disjunctive zero-knowledge proof) using the sigma-rs framework.
//!
//! This example demonstrates how to construct a *non-interactive zero-knowledge proof* (NIZK)
//! of a disjunction (logical OR) between two algebraic statements,
//! using the compositional Sigma protocol framework provided by `sigma-rs`.
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
//! For these statements, the elements $G, H, X_1, X_2, Y2$ are all publicly available to any verifier.
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
    let mut morphismp = LinearRelation::<G>::new();

    // === Allocation phase ===
    // To construct a relation, we first create the variables (scalar, group points)
    // that defines the relation. As they are variables, they are not real "values" (eg. a specific point of $\mathbb{Z}_p$).

    // Allocate a variable for the scalar witness `x`
    let var_x = morphismp.allocate_scalar();

    // Allocate a variable for the basepoint `G`
    let var_G = morphismp.allocate_element();

    // === Constraint phase ===
    // Now that all variables are defined, we describe the relation we want to prove.
    // The variable `X` is allocated now, as it is the result of the computation to be proven.

    // Define the constraint: `X = x * G`
    let var_X = morphismp.allocate_eq(var_x * var_G);

    // === Assignation phase ===
    // We now assign real values to the variables we have defined for our relation above.
    // Since the witness is provided to the function, we only need to assign the group points.

    // Assign the group generator to the corresponding variable `G`
    morphismp.assign_element(var_G, G::generator());

    // Assign the value of the image to the variable `X` (i.e., evaluate the group equation for `x`)
    morphismp.compute_image(&[x]).unwrap();

    // === Output phase ===
    // The relation has been defined and is ready to be used in a protocol.

    // Sanity check: ensure `X = x * G`
    let X = morphismp.morphism.group_elements.get(var_X).unwrap();
    assert_eq!(X, G::generator() * x);

    // Output the relation and the witness for the upcoming proof
    (morphismp, vec![x])
}

/// Construct the relation `(X = x·G, Y = x·H)` and return it along with the witness `x`.
/// This represents a DLEQ (discrete log equality) statement between two basepoints.
/// - `x` is a secret scalar in $\mathbb{Z}_p$.
/// - `G`, `H`, `X`, `Y` are elements in a prime-order group $\mathbb{G}$. `G` in particular is a fixed generator.
#[allow(non_snake_case)]
pub fn dleq<G: Group + GroupEncoding>(x: G::Scalar, H: G) -> (LinearRelation<G>, Vec<G::Scalar>) {
    let mut morphismp = LinearRelation::<G>::new();

    // === Allocation phase ===
    // To construct a relation, we first create the variables (scalar, group points)
    // that defines the relation. As they are variables, they are not real "values" (eg. a specific point of $\mathbb{Z}_p$).

    // Allocate a variable for the scalar witness `x`
    let var_x = morphismp.allocate_scalar();

    // Allocate a variable for the basepoint `G`, `H`
    let [var_G, var_H] = morphismp.allocate_elements();

    // === Constraint phase ===
    // Now that all variables are defined, we describe the relation we want to prove.
    // The variables `X`, `Y` are allocated now, as they are the result of the computations to be proven.

    // Create the constraints:
    // - `X = x * G`
    // - `Y = x * H`
    let _var_X = morphismp.allocate_eq(var_x * var_G);
    let _var_Y = morphismp.allocate_eq(var_x * var_H);

    // === Assignation phase ===
    // We now assign real values to the variables we have defined for our relation above.
    // Since the witness is provided to the function, we only need to assign the group points.

    // Assign the group generator to the corresponding variables `G` and `H`
    morphismp.assign_elements([(var_G, G::generator()), (var_H, H)]);

    // Assign the values of the images to the variable `X` (i.e., evaluate the 2 equations for `x`)
    morphismp.compute_image(&[x]).unwrap();

    // === Output phase ===
    // The relation has been defined and is ready to be used in a protocol.

    // Sanity check: ensure `X = x * G` and `Y = x * H`
    let X = morphismp.morphism.group_elements.get(_var_X).unwrap();
    let Y = morphismp.morphism.group_elements.get(_var_Y).unwrap();
    assert_eq!(X, G::generator() * x);
    assert_eq!(Y, H * x);

    // Output the relation and the witness for the upcoming proof
    (morphismp, vec![x])
}

#[allow(non_snake_case)]
fn main() {
    let mut rng = OsRng;

    // === Step 1: Setup the two relations and the single witness ===
    // We create both relations with our helper functions defined above.
    // The dleq statement is generated normally with the prover's witness.
    // The dlog statement is generated with a random scalar that can be tossed away immediately, since he doesn't know a real witness.

    // Relation 1: DLog — we generate the relation but do *not* keep the randomly generated scalar (it will be simulated in the OR-Proof)
    let _x1 = Scalar::random(&mut rng);
    let (rel1, _) = discrete_logarithm::<G>(_x1);

    // Relation 2: DLEQ — We generate the relation for the known witness `x2`
    let x2 = Scalar::random(&mut rng);
    let H = G::random(&mut rng);
    let (rel2, witness2) = dleq::<G>(x2, H);

    // === Step 2: Compose the relations into an OR protocol ===

    // Wrap each relation into a Sigma protocol
    let proto1 = Protocol::from(rel1);
    let proto2 = Protocol::from(rel2);

    // Compose both protocols using logical OR
    let composed = Protocol::Or(vec![proto1, proto2]);

    // Declare the known witness for the second protocol (index = 1)
    let witness = ProtocolWitness::Or(1, vec![ProtocolWitness::Simple(witness2)]);

    // === Step 3: Convert the OR protocol to a NIZK using Fiat-Shamir ===

    // Convert the protocol instance to a non-interactive protocol via Fiat-Shamir.
    // A domain separator is given as a byte-sequence to identify the current instance being proven.
    let nizk = NISigmaProtocol::<_, ShakeCodec<G>>::new(b"or_proof_example", composed);

    // === Step 4: Generate the proof ===

    // Generate a non-interactive proof using the known witness
    // The `.prove_batchable` method produces a serialized proof that includes the commitment, challenge, and response,
    // suitable for verification *without unpacking* and optimized for use in batch-verification settings.
    let proof = nizk
        .prove_batchable(&witness, &mut rng)
        .expect("Proof generation should succeed");

    // === Step 5: Verify the proof ===

    // Verify that the proof is valid against the composed protocol
    // The `.verify_batchable` method verifies the proof directly from its serialized form.
    // It re-derives the Fiat-Shamir challenge from the commitment and checks the response,
    // without needing to manually deserialize or recompute intermediate values.
    let verified = nizk.verify_batchable(&proof).is_ok();
    println!("OR-proof verified: {verified}");
}
