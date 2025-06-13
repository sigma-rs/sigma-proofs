# sigma-rs: a(n updated) toolkit for Σ-protocols


# WARNING

**THIS IMPLEMENTATION IS NOT YET READY FOR PRODUCTION USE**

While I expect the 1.0 version to be largely unchanged from the current
code, for now there are no stability guarantees on the proofs, so they
should not yet be deployed.

### Background

This crate was originally created as part of [`dalek-cryptography`](https://github.com/dalek-cryptography).
It has been forked:
1. To bring the `zkp` crate up to date with `dalek-cryptography` dependencies.
2. To resolve bugs and incorporate changes to the fiat-shamir transform.
3. To make this effort compatible with the Σ-protocol standardization effort.

This crate has a toolkit for Schnorr-style zero-knowledge proofs over generic [`Group`](https://github.com/zkcrypto/group)s
It provides two levels of API:

* a higher-level, declarative API based around the `define_proof` macro,
  which provides an embedded DSL for specifying proof statements in
  Camenisch-Stadler-like notation:
  ```
  define_proof! {
    vrf_proof,   // Name of the module for generated implementation
    "VRF",       // Label for the proof statement
    (x),         // Secret variables
    (A, G, H),   // Public variables unique to each proof
    (B) :        // Public variables common between proofs
    A = (x * B), // Statements to prove
    G = (x * H)
    }
  ```
  This expands into a module containing an implementation of proving,
  verification, and batch verification.  Proving uses constant-time
  implementations, and the proofs have a derived implementation of
  (memory-safe) serialization and deserialization via Serde.

* a lower-level, imperative API inspired by [Bellman][bellman], which
  provides a constraint system for Schnorr-style statements.  This
  allows programmable construction of proof statements at runtime.  The
  higher-level `define_proof` macro expands into an invocation of the
  lower-level API.
  The lower-level API is contained in the `toolbox` module.

#### Auto-generated benchmarks

The `define_proof` macro builds benchmarks for the generated proof
statements, but because these are generated in the client crate (where
the macro expansion happens), they need an extra step to be enabled.

**To enable generated benchmarks in your crate, do the following**:

* Add a `bench` feature to your crate's `Cargo.toml`;
* Add `#[cfg_attr(feature = "bench", feature(test))]` to your crate's
  `lib.rs` or `main.rs`, to enable Rust's nightly-only benchmark
  feature.

## More information

We include runnable examples to demonstrate how to use the `sigma-rs` toolkit in [examples/](https://github.com/mmaker/sigma-rs/tree/main/examples).

## Funding

This project is funded through [NGI0 Entrust](https://nlnet.nl/entrust), a fund established by [NLnet](https://nlnet.nl) with financial support from the European Commission's [Next Generation Internet](https://ngi.eu) program. Learn more at the [NLnet project page](https://nlnet.nl/project/sigmaprotocols).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)
[<img src="https://nlnet.nl/image/logos/NGI0_tag.svg" alt="NGI Zero Logo" width="20%" />](https://nlnet.nl/entrust)

[bellman]: https://github.com/zkcrypto/bellman
