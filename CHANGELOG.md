# Changelog

Entries are listed in reverse chronological order.

## 0.8.4
* move Criterion to dev-dependencies

## 0.8.3
* switch to Criterion for benchmarking
* remove define_proof benchmarking
* revert `thiserror` to v1 until tor-browser 15.0


## 0.8.2
* remove `nightly` feature, fix clippy warnings

## 0.8.1
* update `thiserror to v2`
* fix tests

## 0.8.0
* update `curve25519-dalek` dependency to 4.0
* update `merlin` dependency to 3
* update `rand` dependency to 0.8
* update `sha2` dependency to 0.10
* remove backend features to be consistent with upstream dalek-cryptography
* fix bug that occurs when public point is the identity 

## 0.7.0

* Update `curve25519-dalek`, `merlin` dependencies to 2.0.
* Switch from `failure` to `thiserror` to provide `std`-compatible errors.
* Correct `curve25519-dalek` feature-selection logic.

## 0.6.2

* Correct minimum `curve25519-dalek` version to 1.0.3, not 1.0.0.

## 0.6.1

* Add metadata for docs.rs.

## 0.6.0

* Rewrite around a constraint system API.

