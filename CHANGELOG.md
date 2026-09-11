# Changelog

Entries are listed in reverse chronological order.

## 0.4.0

Every proof produced by 0.3 is invalid under 0.4, and essentially the
whole public API changed. This is a near-total rewrite tracking the current Fiat-Shamir and sigma-protocols IETF drafts.

### Breaking

- Ported to the new `spongefish` API. Group and scalar codecs live in the new `codec` module as extension traits.
- Dependencies removed: `elliptic-curve`, `rand_core` (and the `rand` feature).
- Proving and verification are free functions:
  `prove_batchable`, `prove_compact`, `verify_batchable`, `verify_compact`, `verify_batch`.
  Each takes a tag, uses `StdHash`, and seeds the prover's randomness from OS
  entropy; each has a single `_with` counterpart taking the transcript sponge,
  an already-derived session identifier, and — for the provers — the randomness.
- Session identifiers are deferred to the application-layer.
- `LinearRelation::compile()` now returns a validated `Instance`, satisfying the draft's representation, serialization, and validation criterias.
- Prover randomness is always `ProverRng` (`spongefish::PrivateRng`); scalars are
  sampled through the decoder rather than from a `CryptoRngCore`.
- `SigmaProtocol` no longer carries message serialization, and its transcript
  types are single-valued; `instance_label` is the draft's `encode[0]`.
- Composition is bound by instance codecs, drops the indicator bytes, and
  encodes public-claim branches with a constant shape.
- Module layout reorganized. 
- `Error::UnassignedGroupVar` removed.
- Witness wiping is unconditional and the `zeroize` feature is gone, along with
  the `secret` module and its `SecretScalar` bound. `ScalarCodec` now requires
  `zeroize::Zeroize`, so a group is usable only if its scalar implements it
  (every curve shipped here does; others can newtype). The feature saved no
  dependency — `zeroize` was already in the graph unconditionally — and a
  feature that narrows a blanket impl is not additive, so enabling it in one
  crate could break a sibling in the same dependency graph.

### Added

- Batch verification following the draft.
- Negative ("invalid") test vectors for P-256 and BLS12-381.
- `LinearRelation::allocate_eq_with` and `compile_with_witness` shortcuts for building public and
  prover-derived statements without intermediate element assignment steps.
- `ComposedInstance::and` accepts an empty branch list, and
  `ComposedInstance::threshold` a threshold of zero. Both are trivially true;
  the empty AND and the 0-of-0 threshold have empty NARG strings.

### Fixed

- Nested composition now proved incorrectly: `Or(Or(A, B), Or(C, D))` would fail to prove and only top-level or branches would work.
- Threshold witness counting is now closer to constant-time.
- `LinearRelation::compute_image` now returns an error for wrong-length or conflicting witnesses
  instead of panicking, and leaves the relation unchanged when image assignment fails.

### Performance

A number of performance improvements: constant-time Straus and MSM improvements; simplification of compact verification, caching of instance image, and batch serialization.
