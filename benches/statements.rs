//! Representative application statement benchmarks.
//!
//! Proving measures image computation, relation compilation, and proof
//! generation. Verification measures relation compilation and proof
//! verification; proof generation is setup and is not timed. Fixture creation,
//! including hash-to-group and per-iteration relation cloning, is never timed.

use std::hint::black_box;

use curve25519_dalek::{RistrettoPoint as G, Scalar};
use divan::Bencher;
use group::Group;
use hash2group::{rfc9380::ExpandMsgXmd, FromHash};
use itertools::Itertools;
use sha2::Sha256;
use sigma_proofs::linear_relation::LinearCombination;
use sigma_proofs::{
    derive_session_id, prove_batchable_with, verify_batchable_with, DefaultHash, LinearRelation,
    ProverRng,
};

const TAG: &[u8] = b"sigma-proofs representative statement benchmarks";
const POINT_DOMAIN: &[u8] = b"sigma-proofs statement benchmark points";

type PointHash = ExpandMsgXmd<Sha256>;

struct Fixture {
    relation: LinearRelation<G>,
    witness: Vec<Scalar>,
}

impl Fixture {
    fn new(relation: LinearRelation<G>, witness: Vec<Scalar>) -> Self {
        Self { relation, witness }
    }
}

fn main() {
    divan::main();
}

fn hashed_point(index: u64) -> G {
    <G as FromHash<PointHash>>::from_hash(POINT_DOMAIN, &index.to_le_bytes())
}

fn discrete_logarithm() -> Fixture {
    let mut relation = LinearRelation::<G>::new();
    let x = relation.allocate_scalar();
    let generator = relation.generator();
    relation.allocate_eq(x * generator);

    let witness = vec![Scalar::from(11u64)];
    Fixture::new(relation, witness)
}

fn dleq() -> Fixture {
    let mut relation = LinearRelation::<G>::new();
    let x = relation.allocate_scalar();
    let generator = relation.generator();
    let h = relation.allocate_element_with(hashed_point(7));
    relation.allocate_eq(x * generator);
    relation.allocate_eq(x * h);

    let witness = vec![Scalar::from(11u64)];
    Fixture::new(relation, witness)
}

fn pedersen_commitment() -> Fixture {
    let mut relation = LinearRelation::<G>::new();
    let [message, blind] = relation.allocate_scalars();
    let generator = relation.generator();
    let h = relation.allocate_element_with(hashed_point(7));
    relation.allocate_eq(message * generator + blind * h);

    let witness = vec![Scalar::from(11u64), Scalar::from(13u64)];
    Fixture::new(relation, witness)
}

fn bbs_blind_commitment() -> Fixture {
    let mut relation = LinearRelation::<G>::new();
    let [blind, message_1, message_2, message_3] = relation.allocate_scalars();
    let q_2 = relation.allocate_element_with(hashed_point(2));
    let j_1 = relation.allocate_element_with(hashed_point(3));
    let j_2 = relation.allocate_element_with(hashed_point(5));
    let j_3 = relation.allocate_element_with(hashed_point(7));
    relation.allocate_eq(blind * q_2 + message_1 * j_1 + message_2 * j_2 + message_3 * j_3);

    let witness = vec![
        Scalar::from(11u64),
        Scalar::from(13u64),
        Scalar::from(17u64),
        Scalar::from(19u64),
    ];
    Fixture::new(relation, witness)
}

fn cmz_wallet_spend() -> Fixture {
    let mut relation = LinearRelation::<G>::new();
    let [balance, price, wallet_blind] = relation.allocate_scalars();
    let wallet_base = relation.allocate_element_with(hashed_point(7));
    let blind_base = relation.allocate_element_with(hashed_point(11));
    let fee = Scalar::from(5u64);
    relation.allocate_eq((balance + price + fee) * wallet_base + wallet_blind * blind_base);

    let witness = vec![
        Scalar::from(101u64),
        Scalar::from(17u64),
        Scalar::from(23u64),
    ];
    Fixture::new(relation, witness)
}

/// The representative range statement from `tests/relations/mod.rs`: prove that
/// a commitment to 822 lies in `[0, 1337)` using weighted bit commitments.
fn range_statement() -> Fixture {
    let input = 822u64;
    let range = 0u64..1337u64;
    let delta = range.end - range.start;
    let whole_bits = (delta - 1).ilog2() as usize;
    let remainder = delta - (1 << whole_bits);

    let mut bases = (0..whole_bits).map(|i| 1 << i).collect::<Vec<_>>();
    bases.push(remainder);

    let generator_value = G::generator();
    let h_value = hashed_point(7);
    let mut relation = LinearRelation::<G>::new();
    let [generator, h] = relation.allocate_elements();
    let bits = relation.allocate_scalars_vec(bases.len());
    let blinds = relation.allocate_scalars_vec(bases.len());
    let second_blinds = relation.allocate_scalars_vec(bases.len());
    let bit_commitments = relation.allocate_elements_vec(bases.len());

    let commitment = relation.allocate_eq(
        generator * Scalar::from(range.start)
            + (0..bases.len())
                .map(|i| (bits[i] * generator) * Scalar::from(bases[i]))
                .sum::<LinearCombination<G>>()
            + (0..bases.len())
                .map(|i| (blinds[i] * h) * Scalar::from(bases[i]))
                .sum::<LinearCombination<G>>(),
    );
    for i in 0..bases.len() {
        relation.append_equation(bit_commitments[i], bits[i] * generator + blinds[i] * h);
        relation.append_equation(
            bit_commitments[i],
            bits[i] * bit_commitments[i] + second_blinds[i] * h,
        );
    }

    let mut rest = input - range.start;
    let mut bit_values = vec![Scalar::ZERO; bases.len()];
    for (i, &base) in bases.iter().enumerate().rev() {
        if rest >= base {
            bit_values[i] = Scalar::ONE;
            rest -= base;
        }
    }
    let blind_values = (0..bases.len())
        .map(|i| Scalar::from((i + 17) as u64))
        .collect::<Vec<_>>();
    let commitment_blind = bases
        .iter()
        .zip_eq(&blind_values)
        .map(|(&base, &blind)| Scalar::from(base) * blind)
        .sum::<Scalar>();
    let second_blind_values = bit_values
        .iter()
        .zip_eq(&blind_values)
        .map(|(&bit, &blind)| (Scalar::ONE - bit) * blind)
        .collect::<Vec<_>>();
    let witness = bit_values
        .iter()
        .chain(&blind_values)
        .chain(&second_blind_values)
        .copied()
        .collect::<Vec<_>>();

    relation.set_elements([(generator, generator_value), (h, h_value)]);
    relation.set_element(
        commitment,
        generator_value * Scalar::from(input) + h_value * commitment_blind,
    );
    for i in 0..bases.len() {
        relation.set_element(
            bit_commitments[i],
            generator_value * bit_values[i] + h_value * blind_values[i],
        );
    }

    Fixture::new(relation, witness)
}

fn bench_prove(bencher: Bencher, fixture: fn() -> Fixture) {
    let Fixture { relation, witness } = fixture();
    let session_id = derive_session_id::<DefaultHash>(TAG);
    let mut rng = ProverRng::from_seed([7u8; 32]);
    bencher
        .with_inputs(|| relation.clone())
        .bench_local_values(|mut relation| {
            black_box(&mut relation)
                .compute_image(black_box(&witness))
                .unwrap();
            let instance = black_box(&relation).compile().unwrap();
            prove_batchable_with::<DefaultHash, _>(
                &session_id,
                black_box(&instance),
                black_box(&witness),
                &mut rng,
            )
            .unwrap()
        });
}

fn bench_verify(bencher: Bencher, fixture: fn() -> Fixture) {
    let Fixture {
        mut relation,
        witness,
    } = fixture();
    let session_id = derive_session_id::<DefaultHash>(TAG);
    relation.compute_image(&witness).unwrap();
    let instance = relation.compile().unwrap();
    let proof = prove_batchable_with::<DefaultHash, _>(
        &session_id,
        &instance,
        &witness,
        &mut ProverRng::from_seed([7u8; 32]),
    )
    .unwrap();
    bencher
        .with_inputs(|| relation.clone())
        .bench_values(|relation| {
            let instance = black_box(&relation).compile().unwrap();
            verify_batchable_with::<DefaultHash, _>(
                &session_id,
                black_box(&instance),
                black_box(proof.as_slice()),
            )
            .unwrap()
        });
}

macro_rules! statement_benches {
    ($module:ident, $fixture:ident) => {
        mod $module {
            use super::*;

            #[divan::bench]
            fn prove(bencher: Bencher) {
                bench_prove(bencher, $fixture);
            }

            #[divan::bench]
            fn verify(bencher: Bencher) {
                bench_verify(bencher, $fixture);
            }
        }
    };
}

statement_benches!(discrete_logarithm, discrete_logarithm);
statement_benches!(dleq, dleq);
statement_benches!(pedersen_commitment, pedersen_commitment);
statement_benches!(bbs_blind_commitment, bbs_blind_commitment);
statement_benches!(cmz_wallet_spend, cmz_wallet_spend);
statement_benches!(range_statement, range_statement);
