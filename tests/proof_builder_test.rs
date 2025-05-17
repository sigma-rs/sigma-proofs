use bls12_381::{G1Projective, Scalar};
use group::ff::Field;

use rand::rngs::OsRng;
use sigma_rs::ProofBuilder;

type G = G1Projective;

#[test]
#[allow(non_snake_case)]
fn discrete_logarithm() {
    let domain_sep = b"hello world";
    let mut rng = OsRng;
    let mut proof_builder = ProofBuilder::<G>::new(domain_sep);

    let scalars = proof_builder.allocate_scalars(1);
    let points = proof_builder.allocate_elements(2);

    let var_x = scalars[0];
    let (var_G, var_X) = (points[0], points[1]);

    proof_builder.append_equation(var_X, &[(var_x, var_G)]);

    let G = G::generator();
    proof_builder.set_elements(&[(var_G, G)]);

    let mut witness = Vec::new();
    witness.push(Scalar::random(rng));

    let X = G * witness[0];
    proof_builder.set_elements(&[(var_X, X)]);

    // Prove and verify a proof
    let proof_bytes = proof_builder.prove(&witness, &mut rng);
    let result = match proof_builder.verify(&proof_bytes) {
        Ok(_) => true,
        _ => false,
    };

    // Prove and verify a proof
    let compact_proof_bytes = proof_builder.prove_compact(&witness, &mut rng);
    let compact_result = match proof_builder.verify_compact(&compact_proof_bytes) {
        Ok(_) => true,
        _ => false,
    };

    assert!(result);
    assert!(compact_result);
}
