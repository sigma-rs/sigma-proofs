# sigma-proofs

A Rust library for building and composing vintage zero-knowledge proofs.

It focuses on Σ-protocols (Sigma protocols) for linear relations over group elements. The Fiat-Shamir transformation turns these interactive protocols into non-interactive proofs suitable for real-world applications.

## Quick Example

Prove knowledge of a discrete logarithm:

```rust
use curve25519_dalek::{RistrettoPoint as G, Scalar};
use group::Group;
use sigma_proofs::{prove_batchable, verify_batchable, LinearRelation};

let witness = [Scalar::from(42u64)];
let public_key = G::generator() * witness[0];

let mut relation = LinearRelation::<G>::new();
let x = relation.allocate_scalar();
relation.allocate_eq_with(public_key, x * relation.generator());

let statement = relation.compile().unwrap();
const TAG: &[u8] = b"my-application DSFS";
let proof = prove_batchable(TAG, &statement, &witness).unwrap();
verify_batchable(TAG, &statement, &proof).unwrap();
```

## Compressed proofs

For a relation with `n` witness scalars, `Compressed` produces a proof with
`1 + 2·⌈log₂(n)⌉` group elements and one scalar:

```rust
use curve25519_dalek::{RistrettoPoint as G, Scalar};
use group::Group;
use sigma_proofs::{compressed::Compressed, LinearRelation};
use spongefish::Narg;

let witness = vec![Scalar::from(3u64), Scalar::from(5u64)];
let mut relation = LinearRelation::<G>::new();
let [x, y] = relation.allocate_scalars();
let h = relation.allocate_element_with(G::generator() * Scalar::from(7u64));
relation.allocate_eq(x * relation.generator() + y * h);
let statement = relation.compile_with_witness(&witness).unwrap();

let session = Narg::derive_session_id(b"my-application compressed");
let (proof, ()) =
    Narg::prove_with_session_id::<Compressed<G>>(&session, &statement, &witness).unwrap();
Narg::verify_with_session_id::<Compressed<G>>(&session, &statement, &proof).unwrap();
```

## Composition

Compile the component statements, combine them with
`ComposedInstance::{and, or}`, and mirror that shape with
`ComposedWitness::{and, or}`. Only the real branch of an OR needs a witness;
the others are simulated.

See [`simple_composition.rs`](examples/simple_composition.rs) for a complete OR
proof. [`schnorr.rs`](examples/schnorr.rs) shows the compact NARG flavor instead
of repeating the batchable flow above.

## Status

**⚠️ NOT YET READY FOR PRODUCTION USE**

This library is under active development. The API is stabilizing, but proof
compatibility between versions is not guaranteed.

## Background

This crate continues the original `zkp` toolkit from [`dalek-cryptography`](https://github.com/dalek-cryptography), modernized with updated dependencies and improved Fiat-Shamir transforms. It implements the general framework for Sigma protocols described in [Maurer (2009)](https://doi.org/10.1007/978-3-642-02384-2_17).

## Funding

This project was funded through [NGI0 Entrust](https://nlnet.nl/entrust), a fund established by [NLnet](https://nlnet.nl) with financial support from the European Commission's [Next Generation Internet](https://ngi.eu) program. Learn more at the [NLnet project page](https://nlnet.nl/project/sigmaprotocols).
