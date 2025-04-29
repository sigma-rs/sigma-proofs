use rand::{Rng, CryptoRng};
use rand::SeedableRng;
use hex;
use rand_chacha::ChaCha20Rng;
use group::{Group, GroupEncoding, ff::Field};
use curve25519_dalek::ristretto::RistrettoPoint;

use sigma_rs::toolbox::sigma::{
    GroupMorphismPreimage,
    SchnorrProof,
    transcript::KeccakTranscript,
    NISigmaProtocol,
};

type G = RistrettoPoint;

// fn msm_pr<G: Group>(scalars: &[G::Scalar], bases: &[G]) -> G {
//     let mut acc = G::identity();
//     for (s, p) in scalars.iter().zip(bases.iter()) {
//         acc += *p * s;
//     }
//     acc
// }


#[allow(non_snake_case)]
fn discrete_logarithm<G: Group + GroupEncoding>(
    rng: &mut (impl Rng + CryptoRng)
) -> (GroupMorphismPreimage<G>, Vec<G::Scalar>) {
    let mut morphismp: GroupMorphismPreimage<G> = GroupMorphismPreimage::new();

    let var_x: usize = 0;
    let (var_G, var_X): (usize, usize) = (0, 1);
    morphismp.allocate_scalars(1);
    morphismp.allocate_elements(2);
    morphismp.append_equation(var_X, &[(var_x, var_G)]);

    let G = G::generator();
    morphismp.set_elements(&[(var_G, G)]);

    let x = G::Scalar::random(&mut *rng);
    let X = G * x;
    assert!(vec![X] == morphismp.morphism.evaluate(&[x]));

    morphismp.set_elements(&[(var_X, X)]);
    (morphismp, vec![x])
}

/// This part tests the implementation of the SigmaProtocol trait for the 
/// SchnorrProof structure as well as the Fiat-Shamir NISigmaProtocol transform
#[allow(non_snake_case)]
#[test]
fn NI_discrete_logarithm() {
    // Seed initialisation
    let mut seed_array = [0u8; 32];  
    let seed_bytes = b"test vector seed";

    // Copy the seed (repeat if needed, pad if smaller)
    seed_array[..seed_bytes.len()].copy_from_slice(seed_bytes);

    // Now create the RNG
    let mut rng = ChaCha20Rng::from_seed(seed_array);
    
    let (morphismp, witness) = discrete_logarithm::<G>(&mut rng);

    // The SigmaProtocol induced by morphismp
    let protocol = SchnorrProof { morphismp };
    // Fiat-Shamir wrapper
    let domain_sep: Vec<u8> = b"yellow submarineyellow submarine".to_vec();
    let mut nizk = NISigmaProtocol::<SchnorrProof<G>, KeccakTranscript<G>, G>::new(&domain_sep, protocol);
    
    // Prove
    let proof_bytes = nizk.prove(&witness, &mut rng);
    // Verify
    let verified = nizk.verify(&proof_bytes).is_ok();
    assert!(verified, "Fiat-Shamir Schnorr proof verification failed");
    println!("{:?}", hex::encode(proof_bytes));
}