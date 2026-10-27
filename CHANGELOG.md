# Changelog: pqblocks-primitives

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-26

### Added
- Initial public release of `pqblocks-primitives`.
- NIST FIPS 203 ML-KEM key encapsulation (`kem_keygen`, `kem_encaps`, `kem_decaps`).
- NIST FIPS 204 ML-DSA digital signatures (`dsa_keygen`, `dsa_sign`, `dsa_verify`).
- NIST FIPS 205 SLH-DSA stateless hash-based digital signatures (`slhdsa_keygen`, `slhdsa_sign`, `slhdsa_verify`).
- Hybrid key exchange engine (`hybrid_encaps`, `hybrid_decaps`, `HybridEncapsulation`) combining ML-KEM and X25519 with HKDF-SHA256/384.
- Automated validation suite with 248 tests including official NIST ACVP golden vector conformance.
- Verified 97% statement coverage and zero leak validation.
