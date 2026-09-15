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

const TAG: &[u8] = b"my-application compressed";
let (proof, ()) = Narg::prove::<Compressed<G>>(TAG, &statement, &witness).unwrap();
Narg::verify::<Compressed<G>>(TAG, &statement, &proof).unwrap();
```

## Composition

Combine relation builders with `&` (AND) and `|` (OR), then compile the
result. Mirror the same operators and parentheses in the witness:

```rust
use curve25519_dalek::{RistrettoPoint as G, Scalar};
use group::Group;
use sigma_proofs::{composition::ComposedWitness, prove_batchable, verify_batchable, LinearRelation};

fn dlog(public_key: G) -> LinearRelation<G> {
    let mut relation = LinearRelation::new();
    let x = relation.allocate_scalar();
    relation.allocate_eq_with(public_key, x * relation.generator());
    relation
}

let x = Scalar::from(42u64);
let left = dlog(G::generator() * Scalar::from(7u64));
let right = dlog(G::generator() * x);
let statement = (left | right).compile()?;
// Only the right branch needs a valid witness; the left is simulated.
let witness = ComposedWitness::<G>::from(vec![Scalar::ZERO]) | vec![x];
const TAG: &[u8] = b"composition-example DSFS";
let proof = prove_batchable(TAG, &statement, &witness)?;
verify_batchable(TAG, &statement, &proof)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Operators consume their operands and create two-branch nodes: `a & b & c`
is `(a & b) & c`, and `&` binds more tightly than `|`. They return a
`ComposedRelation`; compilation validates every leaf and preserves the tree.
The same operators also work on compiled `Instance` and `ComposedInstance`
values. For a flat node with any number of branches, use
`ComposedRelation::{and, or}` (or `ComposedInstance::{and, or}` after
compilation) and `ComposedWitness::{and, or}`. Variables in separate branches
are independent; use one `LinearRelation` for equations that must share a
witness scalar.

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
