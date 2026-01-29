# sigma-proofs

A Rust library for building and composing Σ-protocols (Sigma protocols) for zero-knowledge proofs.

This library focuses on any statement that can be expressed as a linear relation over group elements. Using the Fiat-Shamir transformation, these interactive protocols become non-interactive proofs suitable for real-world applications.

## Quick Example

```rust
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use group::Group;
let mut instance = sigma_proofs::LinearRelation::new();
let mut rng = rand::thread_rng();

// Define the statement:
// Prove knowledge of (x, r) such that C = x·G + r·H (Pedersen commitment)
let [var_x, var_r] = instance.allocate_scalars();
let [var_G, var_H] = instance.allocate_elements();
instance.allocate_eq(var_G * var_x + var_H * var_r);
instance.set_elements([(var_G, RistrettoPoint::generator()), (var_H, RistrettoPoint::random(&mut rng))]);

// Assign the image of the linear map.
let witness = vec![Scalar::random(&mut rng), Scalar::random(&mut rng)];
instance.compute_image(&witness);

// Create a non-interactive argument for the instance.
let nizk = instance.into_nizk(b"your session identifier").unwrap();
let narg_string: Vec<u8> = nizk.prove_batchable(&witness, &mut rng).unwrap();
// Print the narg string.
println!("{}", hex::encode(narg_string));
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

This crate continues the work from the original `zkp` toolkit in [`dalek-cryptography`](https://github.com/dalek-cryptography), modernized with updated dependencies and improved Fiat-Shamir transforms. It implements the general framework for Sigma protocols as described in [Maurer (2009)](https://doi.org/10.1007/978-3-642-02384-2_17).
