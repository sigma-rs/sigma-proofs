# Threat model

Read this document alongside [`../SECURITY.md`](../SECURITY.md), which says how to report a failure of any guarantee stated here.

This library provides zero-knowledge proofs (zkp) for the preimage of a linear map over a prime-order group (Maurer09), together with AND / OR / threshold compositions, and compressed sigma protocols. The zkp is presented as a non-interactive argument via the Fiat-Shamir transformation. It does not provide persistent state at rest, and no protection for replay attacks. Soundness of the argument provided by this library is *computational*: soundness is not expected to hold against quantum adversaries. Zero-knowledge (privacy) is expected to be statistical.

This library is spec-compatible with draft-irtf-cfrg-sigma-protocols and draft-irtf-cfrg-fiat-shamir.

## Trust boundary

The NARG string passed to a verifier is the only untrusted input. 

The instance shall be assumed to be trusted but it is validated (by `compile()`) at construction time. While the instance is validated, whether it captures the intended statement and provides the desired privacy features is a modeling question that belongs to the user.

The session identifier is assumed to have been chosen correctly and sigma-rs won't be able to check if it's appropriately chosen. In particular, this library doesn't offer replay protection, freshness, and key management.

## Assumptions

Tis library relies on the **discrete logarithm** assumption in the chosen group; the **random oracle model** for the chosen permutation (or hash) function (by default, `keccak-f`).

It also relies on the soundness of the `Group` algebra, and reliability of the entropy source for the prover's randomness. Faulty random number generators, or nonce reuse across two proofs will be fatal for zero-knowledge (privacy of the witness). The API is shaped to prevent that from happening by accident, relying on the operating system's randomenss and consuming the prover state before producing a response. If you supply the randomness (`prove_batchable_with`, `prove_compact_with`), you are responsible for nonce uniqueness.

### Verification

A verifier must terminate and return (never panic) for *every* byte string, even adversarially generated. Parsing the NARG string is informed by the instance. The resulting proof satisfies strong simulation extractability. In particular, this means that no adversary should be able to tamper with a NARG string to produce a new NARG string that is also valid (without knowing the witness).

### Proving

The prover checks the *shape* of the witness, never its *validity*. If the caller invokes the prover on a wrong input, the output of the proving function is unpredictable. Implementations may run the zero-knowledge verifier on the output of the prover to check for witness validity.

Witnesses that present an invalid shape (e.g. invalid vector length) return `Err(InvalidWitness)`.

## Domain separation

The specification requires the tag to contain, verbatim, the flavor marker (`DSFS` for batchable, `CMPT` for compact) and the ciphersuite identifier, alongside application context. **The library cannot enforce proper choice of the sesssion identifier, it is responsibility of the caller to provide one.**

## Side channels

This library tries it best to hide the *value* (not the length) of the witness, with constant-time protections. Empirical testing (`tests/dudect.rs`) measures actual binaries, from a finite set of shapes and samples. As such, it cannot certify absence of timing attacks.  Rust and LLVM may introduce branches over secret data. This library implements constant-time group operations and, for OR composition, constant-time selection of the index of the true branch; for threshold composition, the count of satisfied branches. For each OR branch, the simulated and real provers are executed. Branch selection and the compaction that reorders branches are oblivious of the witness. Secret information is erased via `zeroize::Zeroize`.

The instance, the equations of a linear relation, the (group) elements parts of it, and its image, the structure of a composition are considered public information. The session identifier, the NARG string, and the tag are considered non-secret too.

Cache eviction, power analysis, and spectre-class of attacks are not in scope. Neither it is protection and safe erasure of the caller's own copy of the witness data, or handling of prover state inbetween calls (e.g. between `prover_commit` and `prover_response`).

## Assurance measures

| Claim | Evidence |
| --- | --- |
| Memory safety | `unsafe_code` denied across workspace targets and forbidden in library code outside Kani's narrowly scoped tracing exception; Miri over the unit tests on each curve, nightly |
| Verifier totality (§2.1) | Tests that a corrupted proof must be rejected, never accepted, never a panic. `clippy::panic`/`unwrap_used` denied crate-wide; `indexing_slicing` denied on the parsing modules. CI for  |
| Spec conformance | Test vectors from draft-irtf-cfrg-sigma-protocols (P-256, BLS12-381) checksummed against upstream |
| MSM correctness | Tests for all four paths (constant-time and variable-time, generic and per-curve) agree with `sum(base * scalar)` |
| Integer overflow | Full suite re-run in release with `-C overflow-checks=on -C debug-assertions=on`, every pull request |
| OR and THRESH composition timing | `tests/dudect.rs` (empirical, limited shapes — see §6.3); 100 samples per pull request, 50 000 nightly. Statistical only: nothing here is machine-checked |
| Compaction correctness and obliviousness | Kani, nightly. Exhaustive over every mark pattern, at the branch counts the harnesses name (one through nine, twelve and sixteen): that the compaction is the expected permutation, that the marks steer no memory access, and that a threshold prover simulates exactly `n - t` branches whatever it holds. Proved over MIR, so it constrains this source and not the code LLVM emits from it — a `Choice` select lowered back into a branch stays the business of §6.3 |
| Portability | CI builds and tests on `wasm32-wasip1` and `no_std` |
| Witness wiping | Unconditional: `ScalarCodec: Zeroize`, wiped in `WitnessState::drop` and after use in `prover_response`, with the nonces' uniform-byte preimage in `Zeroizing`. Residual exposure enumerated in §6.3 |
| Supply chain | `cargo-deny` (advisories, licenses, bans, sources) in CI, declared MSRV built and tested separately; `--locked` builds |
