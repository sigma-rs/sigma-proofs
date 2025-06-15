//! OR-proof composition example.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use group::Group;
use rand::rngs::OsRng;
use sigma_rs::{
    codec::ShakeCodec,
    composition::{Protocol, ProtocolWitness},
    errors::Error,
    LinearRelation, NISigmaProtocol,
};

type G = RistrettoPoint;
type ProofResult<T> = Result<T, Error>;

#[allow(non_snake_case)]
pub fn discrete_logarithm(x: Scalar) -> (LinearRelation<G>, Vec<Scalar>) {
    let mut relation = LinearRelation::<G>::new();

    let var_x = relation.allocate_scalar();
    let var_G = relation.allocate_element();
    let _var_X = relation.allocate_eq(var_x * var_G);

    relation.set_element(var_G, G::generator());
    relation.compute_image(&[x]).unwrap();

    (relation, vec![x])
}

#[allow(non_snake_case)]
pub fn dleq(x: Scalar, h: G) -> (LinearRelation<G>, Vec<Scalar>) {
    let mut relation = LinearRelation::<G>::new();

    let var_x = relation.allocate_scalar();
    let [var_G, var_H] = relation.allocate_elements();
    let _var_X = relation.allocate_eq(var_x * var_G);
    let _var_Y = relation.allocate_eq(var_x * var_H);

    relation.set_elements([(var_G, G::generator()), (var_H, h)]);
    relation.compute_image(&[x]).unwrap();

    (relation, vec![x])
}

fn create_or_relations(x1: Scalar, x2: Scalar, h: G) -> (Protocol<G>, ProtocolWitness<G>) {
    let (rel1, _) = discrete_logarithm(x1);
    let (rel2, witness2) = dleq(x2, h);

    let proto1 = Protocol::from(rel1);
    let proto2 = Protocol::from(rel2);
    let composed = Protocol::Or(vec![proto1, proto2]);

    let witness = ProtocolWitness::Or(1, vec![ProtocolWitness::Simple(witness2)]);

    (composed, witness)
}

fn prove_or(x1: Scalar, x2: Scalar, h: G) -> ProofResult<Vec<u8>> {
    let mut rng = OsRng;
    let (composed, witness) = create_or_relations(x1, x2, h);
    let nizk = NISigmaProtocol::<_, ShakeCodec<G>>::new(b"or_proof_example", composed);

    nizk.prove_batchable(&witness, &mut rng)
}

fn verify_or(x1: Scalar, x2: Scalar, h: G, proof: &[u8]) -> ProofResult<()> {
    let (composed, _) = create_or_relations(x1, x2, h);
    let nizk = NISigmaProtocol::<_, ShakeCodec<G>>::new(b"or_proof_example", composed);

    nizk.verify_batchable(proof)
}

fn main() {
    let mut rng = OsRng;
    let x1 = Scalar::random(&mut rng);
    let x2 = Scalar::random(&mut rng);
    let h = G::random(&mut rng);

    let proof = prove_or(x1, x2, h).expect("Proof generation failed");
    let verified = verify_or(x1, x2, h, &proof).is_ok();

    println!("OR-proof verified: {verified}");
    println!("Proof bytes: {}", hex::encode(&proof));
}
