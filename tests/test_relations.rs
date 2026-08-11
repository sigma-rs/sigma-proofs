use sigma_proofs::ProverRng;

use sigma_proofs::linear_relation::{Instance, LinearRelation};
use sigma_proofs::{prove_batchable, verify_batchable};
use spongefish::Encoding;

mod relations;
use relations::*;

type G = bls12_381::G1Projective;

/// Generic helper function to test both relation correctness and NIZK functionality
#[test]
fn test_relations() {
    let instance_generators: Vec<(_, &'static dyn Fn(&mut _) -> _)> = vec![
        ("dlog", &discrete_logarithm),
        ("shifted_dlog", &shifted_dlog),
        ("dleq", &dleq),
        ("shifted_dleq", &shifted_dleq),
        ("pedersen_commitment", &pedersen_commitment),
        ("twisted_pedersen_commitment", &twisted_pedersen_commitment),
        ("pedersen_commitment_dleq", &pedersen_commitment_equality),
        ("bbs_blind_commitment", &bbs_blind_commitment),
        ("test_range", &test_range),
        ("weird_linear_combination", &weird_linear_combination),
        ("simple_subtractions", &simple_subtractions),
        ("subtractions_with_shift", &subtractions_with_shift),
        ("cmz_wallet_spend_relation", &cmz_wallet_spend_relation),
        ("nested_affine_relation", &nested_affine_relation),
        ("elgamal_public_subtract", &elgamal_subtraction),
    ];

    for (relation_name, relation_sampler) in instance_generators.iter() {
        let mut rng = ProverRng::from_os_entropy();
        let (canonical_relation, witness): (Instance<G>, _) = relation_sampler(&mut rng);

        // Test the NIZK protocol
        let domain_sep = format!("test-fiat-shamir-{relation_name} DSFS")
            .as_bytes()
            .to_vec();
        let tag: &[u8] = &domain_sep;
        let proof_batchable = prove_batchable(tag, &canonical_relation, &witness)
            .unwrap_or_else(|_| panic!("Failed to create batchable proof for {relation_name}"));
        assert!(
            verify_batchable(tag, &canonical_relation, &proof_batchable).is_ok(),
            "Batchable proof verification failed for {relation_name}"
        );
    }
}

/// Deserialization must be canonical: whatever encoding it accepts must be
/// the encoding it re-emits. The encoded instance is the transcript's domain
/// separator, so an element with two accepted encodings would give one
/// statement two challenges.
///
/// SEC1 is where this bites. Beside the `02`/`03` of a compressed point it
/// defines `05`, the "compact" representation, at the same encoded length;
/// `sec1` decodes it to the same element and re-encodes it as `02`/`03`, and
/// about half of all points admit the rewrite. Ristretto and BLS12-381 carry
/// no tag byte and are canonical already — they are here to pin that nothing
/// they legitimately produce is rejected.
#[test]
fn deserialize_is_canonical() {
    fn canonical<G>()
    where
        G: group::prime::PrimeGroup
            + sigma_proofs::MultiScalarMul
            + sigma_proofs::codec::GroupCodec,
        G::Scalar: sigma_proofs::codec::ScalarCodec,
    {
        use sigma_proofs::codec::ScalarCodec;

        let mut rng = ProverRng::from_os_entropy();
        let mut relation = LinearRelation::<G>::new();
        let x = relation.allocate_scalar();
        let var_h = relation.allocate_element_with(G::generator() * G::Scalar::sample(&mut rng));
        relation.allocate_eq(var_h * x);
        let witness = [G::Scalar::sample(&mut rng)];
        let encoding = relation.compile_with_witness(&witness).unwrap().serialize();

        // The element encodings are a fixed-width run at the tail, so the
        // first byte of each is where a SEC1 tag would live.
        let width = G::element_len();
        let count = encoding.len() / width;
        let shape_len = encoding.len() - count * width;
        assert!(count > 0);
        for i in 0..count {
            for tag in 0x00u8..=0xff {
                let mut mutated = encoding.clone();
                mutated[shape_len + i * width] = tag;
                if let Ok(parsed) = Instance::<G>::deserialize(&mutated) {
                    assert_eq!(
                        parsed.serialize(),
                        mutated,
                        "element {i}: a {tag:#04x} tag was accepted but re-encodes differently, \
                         so this element has two accepted encodings"
                    );
                    // The cached encoding is what the transcript absorbs, so
                    // it must be that same canonical representation.
                    assert_eq!(parsed.encode().as_ref(), parsed.serialize());
                }
            }
        }

        let parsed = Instance::<G>::deserialize(&encoding).unwrap();
        assert_eq!(parsed.serialize(), encoding);
    }

    canonical::<p256::ProjectivePoint>();
    canonical::<k256::ProjectivePoint>();
    canonical::<curve25519_dalek::RistrettoPoint>();
    canonical::<bls12_381::G1Projective>();
}

/// A randomized fused verification equation must remain as strong as checking
/// every equation separately. In particular, opposite shifts in two
/// commitments must not cancel in the fused check.
#[test]
fn fused_verifier_matches_per_equation_verifier() {
    use group::Group;
    use sigma_proofs::traits::SigmaProtocol;

    let mut rng = ProverRng::from_os_entropy();
    let (instance, witness) = dleq::<G>(&mut rng);
    let (commitment, state) = instance.prover_commit(&witness, &mut rng).unwrap();
    let challenge = <G as Group>::Scalar::from(1234567u64);
    let response = instance.prover_response(state, &challenge).unwrap();

    let agrees = |commitment: &Vec<G>, response: &Vec<<G as Group>::Scalar>| {
        let randomness = <G as Group>::Scalar::from(7u64);
        let fused =
            instance.verifier_with_randomness(commitment, &challenge, response, &randomness);
        let plain = instance.verifier(commitment, &challenge, response);
        assert_eq!(fused.is_ok(), plain.is_ok());
        plain.is_ok()
    };

    assert!(agrees(&commitment, &response));

    let shift = G::generator() * <G as Group>::Scalar::from(99u64);
    let mut tampered = commitment.clone();
    tampered[0] += shift;
    tampered[1] -= shift;
    assert!(!agrees(&tampered, &response));
}
