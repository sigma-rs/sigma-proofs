# Security Policy

## Status

`sigma-proofs` is pre-1.0 and the current version **has not been externally audited**. 

Proof encodings are not guaranteed stable between versions, but they will align with [draft-irtf-cfrg-sigma-protocols](https://mmaker.github.io/draft-irtf-cfrg-sigma-protocols/draft-irtf-cfrg-sigma-protocols.html). 

See [`docs/threat-model.md`](docs/threat-model.md) for what the library does and
does not defend against, and for the obligations it places on callers.

## Supported versions

Only the latest published release receives security fixes. 

## Reporting a vulnerability

Report privately through
[GitHub Security Advisories](https://github.com/sigma-rs/sigma-proofs/security/advisories/new).
If you cannot use that channel, email `m@orru.net`.

Please do not open a public issue for a suspected vulnerability.

Include as much as you can: the affected version or commit, the feature set
and curve, a description of the impact, and a reproducer. For a soundness
issue, the strongest possible report is a forged NARG string that verifies
against an instance you have no witness for; for a leakage issue, the
measurement setup and the distinguisher.

We aim to acknowledge within 5 working days. We will agree on a disclosure
timeline with you, and will credit you in the advisory and changelog unless
you ask otherwise.

## What is in scope

- **Soundness**: any way to make `verify_batchable`, `verify_compact`, or
  `verify_batch` accept without a witness for the instance, including
  malleability of an existing NARG string into another accepted one.
- **Zero-knowledge**: any way to recover information about the witness — or,
  for an OR composition, about *which* branch was taken — from proofs,
  timing, or memory behavior. See the constant-time policy in the threat
  model for exactly which values are claimed secret.
- **Verifier denial of service**: any input that makes a verifier panic,
  abort, hang, or allocate unboundedly. The verifier is expected to be
  total on arbitrary byte strings.
- **Fiat-Shamir transcript defects**: missing domain separation, instance
  binding gaps, or challenge derivation that deviates from
  draft-irtf-cfrg-fiat-shamir.
- **Specification conformance**: divergence from
  draft-irtf-cfrg-sigma-protocols that changes which proofs verify.

## What is out of scope

- Misuse that the API documents as the caller's responsibility — most
  importantly tags that omit the flavor marker or ciphersuite identifier,
  session identifiers not derived through the transcript sponge, and
  witnesses that do not satisfy the instance. These are contract violations,
  not vulnerabilities; see the threat model.
- Vulnerabilities in dependencies, unless this crate's use of them is what
  makes them exploitable. Report those upstream; tell us too, so we can
  bump.
- Timing variation in values the threat model designates public.
- Panics from programmer error on the *proving* side (arity mismatches,
  unassigned variables). The prover is trusted with its own inputs; the
  verifier is not.
