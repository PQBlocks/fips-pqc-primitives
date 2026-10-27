# Verification Report: pqblocks-primitives

This report documents empirical verification results across supported Python runtimes.

## Verification Matrix

- **Package**: `pqblocks-primitives`
- **Version**: 0.1.0
- **Test Suite**: 248 automated tests
- **Coverage**: 97% statement coverage (294/304 statements)

| Python Version | Wheel Build | Test Suite | Examples Execution | Gate Status |
|---|---|---|---|---|
| Python 3.11 | PASS | 248 passed | 2 examples passed | **PASS** |
| Python 3.12 | PASS | 248 passed | 2 examples passed | **PASS** |
| Python 3.13 | PASS | 248 passed | 2 examples passed | **PASS** |
| Python 3.14 | PASS | 248 passed | 2 examples passed | **PASS** |

## Executed Examples

1. `examples/quickstart.py`: Validates basic ML-KEM-512 encapsulation/decapsulation and ML-DSA-65 signing/verification.
2. `examples/02_hybrid_kem_and_slhdsa.py`: Validates hybrid ML-KEM-768 + X25519 key encapsulation and SLH-DSA-SHA2-128s signatures with domain separation context strings.

## Zero Leaks Verification

Scanned repository files against internal patterns and markers. Result: **0 leak hits**.
