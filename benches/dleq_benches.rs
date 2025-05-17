// -*- coding: utf-8; mode: rust; -*-
//
// To the extent possible under law, the authors have waived all
// copyright and related or neighboring rights to zkp,
// using the Creative Commons "CC0" public domain dedication.  See
// <http://creativecommons.org/publicdomain/zero/1.0/> for full
// details.
//
// Authors:
// - Henry de Valence <hdevalence@hdevalence.ca>

use criterion::{criterion_group, criterion_main, Criterion};
extern crate bincode;
extern crate curve25519_dalek;
extern crate serde;
extern crate serde_derive;
extern crate sha2;
extern crate sigma_rs;

mod dleq_benches {
    use self::sha2::Sha512;
    use super::*;
    use curve25519_dalek::constants as dalek_constants;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use sigma_rs::old::Transcript;
    use sigma_rs::old::{
        batch_verifier::BatchVerifier, prover::Prover, verifier::Verifier, SchnorrCS,
    };

    #[allow(non_snake_case)]
    fn dleq_statement<CS: SchnorrCS>(
        cs: &mut CS,
        x: CS::ScalarVar,
        A: CS::PointVar,
        B: CS::PointVar,
        G: CS::PointVar,
        H: CS::PointVar,
    ) {
        cs.constrain(A, vec![(x, G)]);
        cs.constrain(B, vec![(x, H)]);
    }

    #[allow(non_snake_case)]
    fn create_compact_dleq(c: &mut Criterion) {
        let G = dalek_constants::RISTRETTO_BASEPOINT_POINT;
        let H = RistrettoPoint::hash_from_bytes::<Sha512>(G.compress().as_bytes());

        let x = Scalar::from(89327492234u64);
        let A = G * x;
        let B = H * x;

        c.bench_function("Create compat dleq", move |b| {
            b.iter(|| {
                let mut transcript = Transcript::new(b"DLEQTest");
                let mut prover = Prover::new(b"DLEQProof", &mut transcript);

                let var_x = prover.allocate_scalar(b"x", x);
                let (var_G, _) = prover.allocate_point(b"G", G);
                let (var_H, _) = prover.allocate_point(b"H", H);
                let (var_A, _cmpr_A) = prover.allocate_point(b"A", A);
                let (var_B, _cmpr_B) = prover.allocate_point(b"B", B);

                dleq_statement(&mut prover, var_x, var_A, var_B, var_G, var_H);

                prover.prove_compact()
            })
        });
    }

    #[allow(non_snake_case)]
    fn verify_compact_dleq(c: &mut Criterion) {
        let G = dalek_constants::RISTRETTO_BASEPOINT_POINT;
        let H = RistrettoPoint::hash_from_bytes::<Sha512>(G.compress().as_bytes());

        let (proof, cmpr_A, cmpr_B) = {
            let x = Scalar::from(89327492234u64);

            let A = G * x;
            let B = H * x;

            let mut transcript = Transcript::new(b"DLEQTest");
            let mut prover = Prover::new(b"DLEQProof", &mut transcript);

            // XXX committing var names to transcript forces ordering (?)
            let var_x = prover.allocate_scalar(b"x", x);
            let (var_G, _) = prover.allocate_point(b"G", G);
            let (var_H, _) = prover.allocate_point(b"H", H);
            let (var_A, cmpr_A) = prover.allocate_point(b"A", A);
            let (var_B, cmpr_B) = prover.allocate_point(b"B", B);

            dleq_statement(&mut prover, var_x, var_A, var_B, var_G, var_H);

            (prover.prove_compact(), cmpr_A, cmpr_B)
        };

        let cmpr_G = G.compress();
        let cmpr_H = H.compress();

        c.bench_function("Verify compact dleq", move |b| {
            b.iter(|| {
                let mut transcript = Transcript::new(b"DLEQTest");
                let mut verifier = Verifier::new(b"DLEQProof", &mut transcript);

                let var_x = verifier.allocate_scalar(b"x");
                let var_G = verifier.allocate_point(b"G", cmpr_G).unwrap();
                let var_H = verifier.allocate_point(b"H", cmpr_H).unwrap();
                let var_A = verifier.allocate_point(b"A", cmpr_A).unwrap();
                let var_B = verifier.allocate_point(b"B", cmpr_B).unwrap();

                dleq_statement(&mut verifier, var_x, var_A, var_B, var_G, var_H);

                verifier.verify_compact(&proof)
            })
        });
    }

    #[allow(non_snake_case)]
    fn create_batchable_dleq(c: &mut Criterion) {
        let G = dalek_constants::RISTRETTO_BASEPOINT_POINT;
        let H = RistrettoPoint::hash_from_bytes::<Sha512>(G.compress().as_bytes());

        let x = Scalar::from(89327492234u64);
        let A = G * x;
        let B = H * x;

        c.bench_function("Create batchable dleq", move |b| {
            b.iter(|| {
                let mut transcript = Transcript::new(b"DLEQTest");
                let mut prover = Prover::new(b"DLEQProof", &mut transcript);

                let var_x = prover.allocate_scalar(b"x", x);
                let (var_G, _) = prover.allocate_point(b"G", G);
                let (var_H, _) = prover.allocate_point(b"H", H);
                let (var_A, _cmpr_A) = prover.allocate_point(b"A", A);
                let (var_B, _cmpr_B) = prover.allocate_point(b"B", B);

                dleq_statement(&mut prover, var_x, var_A, var_B, var_G, var_H);

                prover.prove_batchable()
            })
        });
    }

    #[allow(non_snake_case)]
    fn verify_batchable_dleq(c: &mut Criterion) {
        let G = dalek_constants::RISTRETTO_BASEPOINT_POINT;
        let H = RistrettoPoint::hash_from_bytes::<Sha512>(G.compress().as_bytes());

        let (proof, cmpr_A, cmpr_B) = {
            let x = Scalar::from(89327492234u64);

            let A = G * x;
            let B = H * x;

            let mut transcript = Transcript::new(b"DLEQTest");
            let mut prover = Prover::new(b"DLEQProof", &mut transcript);

            let var_x = prover.allocate_scalar(b"x", x);
            let (var_G, _) = prover.allocate_point(b"G", G);
            let (var_H, _) = prover.allocate_point(b"H", H);
            let (var_A, cmpr_A) = prover.allocate_point(b"A", A);
            let (var_B, cmpr_B) = prover.allocate_point(b"B", B);

            dleq_statement(&mut prover, var_x, var_A, var_B, var_G, var_H);

            (prover.prove_batchable(), cmpr_A, cmpr_B)
        };

        let cmpr_G = G.compress();
        let cmpr_H = H.compress();

        c.bench_function("Verify batchable dleq", move |b| {
            b.iter(|| {
                let mut transcript = Transcript::new(b"DLEQTest");
                let mut verifier = Verifier::new(b"DLEQProof", &mut transcript);

                let var_x = verifier.allocate_scalar(b"x");
                let var_G = verifier.allocate_point(b"G", cmpr_G).unwrap();
                let var_H = verifier.allocate_point(b"H", cmpr_H).unwrap();
                let var_A = verifier.allocate_point(b"A", cmpr_A).unwrap();
                let var_B = verifier.allocate_point(b"B", cmpr_B).unwrap();

                dleq_statement(&mut verifier, var_x, var_A, var_B, var_G, var_H);

                verifier.verify_batchable(&proof)
            })
        });
    }

    #[allow(non_snake_case)]
    fn batch_verify_batchable_dleq_helper(c: &mut Criterion) {
        let G = dalek_constants::RISTRETTO_BASEPOINT_POINT;
        let H = RistrettoPoint::hash_from_bytes::<Sha512>(G.compress().as_bytes());

        static BATCH_SIZES: [usize; 4] = [1, 4, 16, 64];

        // Benchmark batch verification for all the above batch sizes

        for size in BATCH_SIZES {
            let mut proofs = Vec::new();
            let mut cmpr_As = Vec::new();
            let mut cmpr_Bs = Vec::new();
            for j in 0..size {
                let (proof, cmpr_A, cmpr_B) = {
                    let x = Scalar::from((j as u64) + 89327492234u64);

                    let A = G * x;
                    let B = H * x;

                    let mut transcript = Transcript::new(b"DLEQBatchTest");
                    let mut prover = Prover::new(b"DLEQProof", &mut transcript);

                    // XXX committing var names to transcript forces ordering (?)
                    let var_x = prover.allocate_scalar(b"x", x);
                    let (var_G, _) = prover.allocate_point(b"G", G);
                    let (var_H, _) = prover.allocate_point(b"H", H);
                    let (var_A, cmpr_A) = prover.allocate_point(b"A", A);
                    let (var_B, cmpr_B) = prover.allocate_point(b"B", B);

                    dleq_statement(&mut prover, var_x, var_A, var_B, var_G, var_H);

                    (prover.prove_batchable(), cmpr_A, cmpr_B)
                };
                proofs.push(proof);
                cmpr_As.push(cmpr_A);
                cmpr_Bs.push(cmpr_B);
            }

            c.bench_function("Batch verify batchable dleq helper", move |b| {
                b.iter(|| {
                    let mut transcripts = vec![Transcript::new(b"DLEQBatchTest"); size];
                    let transcript_refs = transcripts.iter_mut().collect();
                    let mut verifier =
                        BatchVerifier::new(b"DLEQProof", size, transcript_refs).unwrap();
                    let var_x = verifier.allocate_scalar(b"x");
                    let var_G = verifier.allocate_static_point(b"G", G.compress()).unwrap();
                    let var_H = verifier.allocate_static_point(b"H", H.compress()).unwrap();
                    let var_A = verifier
                        .allocate_instance_point(b"A", cmpr_As.clone())
                        .unwrap();
                    let var_B = verifier
                        .allocate_instance_point(b"B", cmpr_Bs.clone())
                        .unwrap();
                    dleq_statement(&mut verifier, var_x, var_A, var_B, var_G, var_H);

                    assert!(verifier.verify_batchable(&proofs).is_ok());
                })
            });
        }
    }
    criterion_group! {
        name = dleq_benches;
        config = Criterion::default();
        targets =
        verify_compact_dleq,
        create_compact_dleq,
        create_batchable_dleq,
        verify_batchable_dleq,
        batch_verify_batchable_dleq_helper,
    }
}
criterion_main!(dleq_benches::dleq_benches);
