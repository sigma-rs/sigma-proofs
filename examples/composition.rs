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

/// Morphism for knowledge of a discrete logarithm relative to a fixed basepoint.
#[allow(non_snake_case)]
pub fn discrete_logarithm<G: Group + GroupEncoding>(
    x: G::Scalar,
) -> (LinearRelation<G>, Vec<G::Scalar>) {
    let mut morphismp: LinearRelation<G> = LinearRelation::new();

    let var_x = morphismp.allocate_scalar();
    let var_G = morphismp.allocate_element();

    let var_X = morphismp.allocate_eq(var_x * var_G);

    morphismp.assign_element(var_G, G::generator());
    morphismp.compute_image(&[x]).unwrap();

    let X = morphismp.morphism.group_elements.get(var_X).unwrap();

    assert_eq!(X, G::generator() * x);
    (morphismp, vec![x])
}

/// Morphism for knowledge of a discrete logarithm equality between two pairs.
#[allow(non_snake_case)]
pub fn dleq<G: Group + GroupEncoding>(x: G::Scalar, H: G) -> (LinearRelation<G>, Vec<G::Scalar>) {
    let mut morphismp: LinearRelation<G> = LinearRelation::new();

    let var_x = morphismp.allocate_scalar();
    let [var_G, var_H] = morphismp.allocate_elements();

    let var_X = morphismp.allocate_eq(var_x * var_G);
    let var_Y = morphismp.allocate_eq(var_x * var_H);

    morphismp.assign_elements([(var_G, G::generator()), (var_H, H)]);
    morphismp.compute_image(&[x]).unwrap();

    let X = morphismp.morphism.group_elements.get(var_X).unwrap();
    let Y = morphismp.morphism.group_elements.get(var_Y).unwrap();

    assert_eq!(X, G::generator() * x);
    assert_eq!(Y, H * x);
    (morphismp, vec![x])
}

#[allow(non_snake_case)]
fn main() {
    let mut rng = OsRng;

    // === Step 1: Define the two relations ===

    // Relation 1: Knowledge of discrete log, but *no* witness (we don't know x1)
    let _x1 = Scalar::random(&mut rng);
    let (rel1, _) = discrete_logarithm::<G>(_x1); // we're *not* going to use _x1

    // Relation 2: DLEQ (discrete log equality), *with* known witness x2
    let x2 = Scalar::random(&mut rng);
    let H = G::random(&mut rng);
    let (rel2, witness2) = dleq::<G>(x2, H);

    // === Step 2: Compose them into an OR protocol ===

    // Wrap the relations into a Protocol
    let proto1 = Protocol::from(rel1);
    let proto2 = Protocol::from(rel2);
    let composed = Protocol::Or(vec![proto1, proto2]);

    // Declare the witness: we know the second statement (index 1), with its witness
    let witness = ProtocolWitness::Or(1, vec![ProtocolWitness::Simple(witness2)]);

    // === Step 3: Wrap in Fiat-Shamir to get a non-interactive proof system ===

    let nizk = NISigmaProtocol::<_, ShakeCodec<G>>::new(b"or_proof_example", composed);

    // === Step 4: Prove ===

    let proof = nizk.prove_batchable(&witness, &mut rng).unwrap();

    // === Step 4: Verify ===
    assert!(
        nizk.verify_batchable(&proof).is_ok(),
        "OR-proof failed to verify"
    );

    println!("Simplified OR-proof succeeded and verified.");
}
