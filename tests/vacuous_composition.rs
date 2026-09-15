//! Regressions for vacuous composition branches and short witnesses found by
//! fuzzing.

use curve25519_dalek::ristretto::RistrettoPoint as G;
use sigma_proofs::composition::{ComposedInstance, ComposedWitness};
use sigma_proofs::errors::InvalidWitness;
use sigma_proofs::{prove_batchable, prove_compact, ProverRng};

#[allow(dead_code)]
mod relations;
use relations::*;

const BATCH_TAG: &[u8] = b"vacuous composition tests DSFS";

#[test]
fn short_witnesses_are_errors_not_panics() {
    let mut rng = ProverRng::from_os_entropy();
    let (instance, _) = discrete_logarithm::<G>(&mut rng);
    let cases = [
        (
            ComposedInstance::or([instance.clone()]).unwrap(),
            ComposedWitness::or([Vec::new()]),
        ),
        (
            ComposedInstance::threshold(1, [instance]).unwrap(),
            ComposedWitness::threshold([Vec::new()]),
        ),
    ];

    for (relation, witness) in cases {
        assert!(matches!(
            prove_batchable(BATCH_TAG, &relation, &witness),
            Err(InvalidWitness)
        ));
    }
}

#[test]
fn impossible_thresholds_reject_mismatched_witness_shapes() {
    let mut rng = ProverRng::from_os_entropy();
    let (instance, witness) = discrete_logarithm::<G>(&mut rng);
    let relation = ComposedInstance::threshold(2, [instance]).unwrap();
    for witness in [
        ComposedWitness::threshold(Vec::<ComposedWitness<G>>::new()),
        ComposedWitness::threshold([witness.clone(), witness.clone()]),
        ComposedWitness::or([witness]),
        ComposedWitness::Claim,
    ] {
        assert!(matches!(
            prove_batchable(BATCH_TAG, &relation, &witness),
            Err(InvalidWitness)
        ));
        assert!(matches!(
            prove_compact(b"vacuous composition tests CMPT", &relation, &witness),
            Err(InvalidWitness)
        ));
    }
}
