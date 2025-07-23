# sigma-rs

A Rust library for building and composing Σ-protocols (Sigma protocols) for zero-knowledge proofs.

## What is sigma-rs?

This library provides a flexible framework for creating zero-knowledge proofs for any statement expressible as a linear relation over group elements. Using the Fiat-Shamir transformation, these interactive protocols become non-interactive proofs suitable for real-world applications.

## Quick Example

```rust
use sigma_rs::{LinearRelation, Protocol, ProtocolWitness, Nizk};
use sigma_rs::codec::ShakeCodec;
use curve25519_dalek::RistrettoPoint as G;

// Prove knowledge of (x, r) such that C = x·G + r·H (Pedersen commitment)
let mut relation = LinearRelation::<G>::new();

// Allocate variables
let x = relation.allocate_scalar();
let r = relation.allocate_scalar();
let [G_var, H_var] = relation.allocate_elements();

// Define constraint: C = x·G + r·H
let C = relation.allocate_eq(x * G_var + r * H_var);

// Set public values and compute the commitment
relation.set_elements([(G_var, G::generator()), (H_var, H)]);
relation.compute_image(&[x_val, r_val]).unwrap();

// Create non-interactive proof
let nizk = relation.into_nizk(b"pedersen-proof");
let proof = nizk.prove_batchable(&witness, &mut rng)?;
```

## Composition Example

Prove complex statements with AND/OR logic:

```rust
// Prove: (I know x for A = x·G) OR (I know y,z for B = y·G AND C = z·H)
let or_protocol = Protocol::Or(vec![
    Protocol::from(dlog_relation),           // First option
    Protocol::And(vec![                      // Second option
        Protocol::from(relation_B),
        Protocol::from(relation_C),
    ])
]);

// If we know the second option, create witness for index 1
let witness = ProtocolWitness::Or(1, vec![
    ProtocolWitness::And(vec![
        ProtocolWitness::Simple(vec![y]),
        ProtocolWitness::Simple(vec![z]),
    ])
]);
```

## Examples

See the [examples/](examples/) directory:
- `schnorr.rs` - Discrete logarithm proof
- `simple_composition.rs` - OR-proof composition

## Status

**⚠️ NOT YET READY FOR PRODUCTION USE**

This library is under active development. While the API is stabilizing, there are no guarantees on proof compatibility between versions.

## Background

This crate continues the work from the original `zkp` toolkit in [`dalek-cryptography`](https://github.com/dalek-cryptography), modernized with updated dependencies and improved Fiat-Shamir transforms. It implements the general framework for Sigma protocols as described in [Maurer (2009)](https://doi.org/10.1007/978-3-642-02384-2_6).

## Funding

This project is funded through [NGI0 Entrust](https://nlnet.nl/entrust), a fund established by [NLnet](https://nlnet.nl) with financial support from the European Commission's [Next Generation Internet](https://ngi.eu) program. Learn more at the [NLnet project page](https://nlnet.nl/project/sigmaprotocols).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)
[<img src="https://nlnet.nl/image/logos/NGI0_tag.svg" alt="NGI Zero Logo" width="20%" />](https://nlnet.nl/entrust)
