//! Example: simple Schnorr proof of knowledge using the sigma-rs framework.
//!
//! This example demonstrates how to prove knowledge of a discrete logarithm in a group $\mathbb{G}$ of prime order $p$ where the discrete logarithm problem is hard,
//! using the Sigma protocol abstraction provided by `sigma-rs`.
//!
//! More precisely, the prover convinces a verifier that it knows a secret $x$ such that: $$P = x \cdot G$$
//!
//! where $G$ is a fixed generator of $\mathbb{G}$ and $P$ is an element of the group.
//!
//! ---
//!
//! In `sigma-rs`, this is achieved using three core abstractions:
//!
//! 1. [`LinearRelation`] — describes the *morphism* (algebraic relation) between secret scalars and group elements.
//!    This forms the mathematical statement of the protocol. In our case, $P = x \cdot G$.
//!
//! 2. [`SchnorrProtocol`] — defines the interactive Sigma protocol for the given morphism.
//!    This handles the commit-challenge-response structure of the protocol, following the standard Sigma protocol flow:
//!     - P → V: commit $K = r·G$
//!     - V → P: challenge $c$
//!     - P → V: response $s = r + c·x$
//!
//! 3. [`NISigmaProtocol`] — wraps the interactive protocol using the Fiat-Shamir transformation,
//!    converting it to a *non-interactive zero-knowledge proof* (NIZK) by deriving the challenge $c$
//!    from a transcript hash using a [`Codec`] (here, [`ShakeCodec`]).
//!
//! The codec ensures domain separation and deterministic Fiat-Shamir challenges,
//! yielding secure, standalone proofs.
//!
//! ---
//!
//! This example uses the Ristretto group from `curve25519-dalek`, which provides a prime-order group
//! suitable for secure zero-knowledge protocols.
use curve25519_dalek::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use group::{Group, GroupEncoding};
use rand::rngs::OsRng;

use sigma_rs::codec::ShakeCodec;
use sigma_rs::fiat_shamir::NISigmaProtocol;
use sigma_rs::linear_relation::LinearRelation;
use sigma_rs::schnorr_protocol::SchnorrProtocol;

/// Construct the relation `P = x·G` and return it along with the witness `x`:
/// - `x` is an element from a group of prime order $p$, typically $\mathbb{Z}_p$,
/// - `P`, `G` are elements over a group $\mathbb{G}$ of order $p$.
#[allow(non_snake_case)]
pub fn discrete_logarithm<G: Group + GroupEncoding>(
    x: G::Scalar,
) -> (LinearRelation<G>, Vec<G::Scalar>) {
    let mut morphismp: LinearRelation<G> = LinearRelation::new();

    // === Allocation phase ===
    // To construct a relation, we first create the variables (scalar, group points)
    // that defines the relation. As they are variables, they are not real "values" (eg. a specific point of $\mathbb{Z}_p$).

    // Allocate a variable for the scalar witness `x`
    let var_x = morphismp.allocate_scalar();

    // Allocate a variable for the group element `G` (the generator)
    let var_G = morphismp.allocate_element();

    // === Constraint phase ===
    // Now that all variables are defined, we describe the relation we want to prove.
    // The variable `P` is allocated now, as it is the result of the computation to be proven.

    // Create the constraint `P = x * G`
    let var_P = morphismp.allocate_eq(var_x * var_G);

    // === Assignation phase ===
    // We now assign real values to the variables we have defined for our relation above.
    // Since the witness is provided to the function, we only need to assign the group points.

    // Assign the group generator to the corresponding variable `G`
    morphismp.assign_element(var_G, G::generator());

    // Assign the value of the image to the variable `P` (i.e., evaluate the group equation for `x`)
    morphismp.compute_image(&[x]).unwrap();

    // === Output phase ===
    // The relation has been defined and is ready to be used in a protocol.

    // Sanity check: ensure `P = x * G`
    let P = morphismp.morphism.group_elements.get(var_P).unwrap();
    assert_eq!(P, G::generator() * x);

    // Output the relation and the witness for the upcoming proof
    (morphismp, vec![x])
}

#[allow(non_snake_case)]
fn main() {
    // === Step 1: Setup the relation and witness ===

    // Choose a secret scalar `x` (the witness).
    let x = Scalar::random(&mut OsRng);

    // Construct a relation `P = x * G` and retrieve:
    // - The constraint system defined in the helper function above.
    // - The witness in vector format (useful for proofs with multiple witnesses).
    let (relation, witness) = discrete_logarithm(x);

    // === Step 2: Create the Schnorr protocol and wrap it with Fiat-Shamir ===

    // Build the Sigma protocol instance from the relation.
    let schnorr = SchnorrProtocol::<RistrettoPoint>::from(relation);

    // Convert the Sigma protocol instance to a non-interactive protocol via Fiat-Shamir.
    // A domain separator is given as a byte-sequence to identify the current instance being proven.
    let nizk = NISigmaProtocol::<_, ShakeCodec<RistrettoPoint>>::new(b"schnorr-example", schnorr);

    // === Step 3: Generate the proof ===

    // Generate a non-interactive proof with the witness.
    // The non-interactive proof contains the 3 elements of a sigma protocol transcript: a commitment, a challenge, and a response.
    // This transcript can be transmitted by the prover to any verifier, without revealing any secret information about the prover.
    let (commitment, challenge, response) = nizk.prove(&witness, &mut OsRng).unwrap();

    // === Step 4: Verify the proof ===

    // Verification requires checking the proof against the transcript and constraint system.
    // The verifier can be convinced that the prover indeed knows `x` so that `P = x*G`. This doesn't require any interaction with the prover other than receiving the transcript.
    let verified = nizk.verify(&commitment, &challenge, &response).is_ok();
    println!("Schnorr NIZK proof verified: {verified}");
}
