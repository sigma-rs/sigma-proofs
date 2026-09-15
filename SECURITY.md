# Security Policy

## Status

`sigma-proofs` is pre-1.0 and the current version **has not been externally audited**. 

Proof encodings are not guaranteed stable between versions, but they will align with [draft-irtf-cfrg-sigma-protocols](https://mmaker.github.io/draft-irtf-cfrg-sigma-protocols/draft-irtf-cfrg-sigma-protocols.html). 

See [`docs/threat-model.md`](docs/threat-model.md) for what the library defends against, and for what are the obligations of this library's adopters.

## Supported versions

Only the latest published release receives security fixes. 

## Reporting a vulnerability

Report privately through
[GitHub Security Advisories](https://github.com/sigma-rs/sigma-proofs/security/advisories/new).
Alternatively, email `m@orru.net`.

Please do not open a public issue for a suspected vulnerability.

Include as much as you can: the affected version or commit, the feature set and curve, a description of the impact, and a reproducer. For a soundness issue, the strongest possible report is a NARG string that verifies against an instance you have no witness for; for a leakage issue, the measurement setup and the distinguisher.

We aim to acknowledge within 5 working days. We will agree on a disclosure timeline with you, and will credit you in the advisory and changelog unless you ask otherwise.

## What is in scope

The scope for security report is restricted to Maurer proofs, and more specifically attacks for: 

- **simulation extractability**: any way to make `verify_batchable`,`verify_compact`, or  `verify_batch` accept without a witness for the instance, including malleability of an existing NARG string into another accepted one, in the "strong simulation extractability" sense.
- **zero-knowledge**: any way to recover information about the witness. For an OR composition, this includes *which* branch was taken, such timing or memory behavior. See the constant-time policy for side-channel concerns.
- **denial of service**: any input that makes a verifier panic, abort, hang, or allocate unboundedly under attacker-controlled input.
- **Fiat-Shamir issues**: weak fiat shamir, improper uses of the random oracle, or challenge derivation that deviates from draft-irtf-cfrg-fiat-shamir.
- **Specification conformance**: divergence from draft-irtf-cfrg-sigma-protocols that changes which proofs verify.

This includes modules `fiat_shamir`, `composition`, `codec`, `msm` and `linear_relation`. On the other hand, this is out of scope:

- Misuse that the API documents as the caller's responsibility. For instance,
  conflicting session identifiers, instances that have a trivial kernel.
- Vulnerabilities in dependencies, unless this crate's use of them is what
  makes them exploitable. Report those upstream; tell us too, so we can
  bump.
