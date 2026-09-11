//! Regressions for vacuous composition branches and short witnesses found by
//! fuzzing.

use curve25519_dalek::ristretto::RistrettoPoint as G;
use sigma_proofs::composition::{ComposedInstance, ComposedWitness};
use sigma_proofs::errors::InvalidWitness;
use sigma_proofs::{prove_batchable, ProverRng};

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
fn invalid_compositions_are_rejected_at_construction() {
    let mut rng = ProverRng::from_os_entropy();
    let (instance, _) = discrete_logarithm::<G>(&mut rng);

    assert!(ComposedInstance::<G>::or(Vec::<ComposedInstance<G>>::new()).is_err());
    assert!(ComposedInstance::<G>::threshold(1, Vec::<ComposedInstance<G>>::new()).is_err());
    assert!(ComposedInstance::threshold(0, [instance.clone()]).is_err());
    assert!(ComposedInstance::threshold(2, [instance]).is_err());
    // The empty sum is the identity, so an empty claim holds unconditionally.
    assert!(ComposedInstance::<G>::claim([]).is_err());
}
