# Testing: pqblocks-primitives

## Test Harness Overview

`pqblocks-primitives` incorporates an extensive 248-test verification suite covering unit behaviors, boundary conditions, edge cases, and official NIST ACVP golden test vectors.

### Test Execution

Run the suite with pytest:

```bash
pytest -v
```

With coverage measurement:

```bash
pytest --cov=pqblocks_primitives --cov-report=term-missing
```

## Coverage Report

The test suite achieves **97% statement coverage** across the source library:

| Module | Statements | Missing | Coverage |
|---|---|---|---|
| `pqblocks_primitives/__init__.py` | 304 | 10 | **97%** |

## Test Scenarios Covered

1. **NIST ACVP Official Vector Conformance**:
   - `ML-KEM-encapDecap-FIPS203`: Decapsulation tests validating deterministic shared-secret recovery against official vectors.
   - `ML-DSA-sigVer-FIPS204`: Verification tests across ML-DSA-44, ML-DSA-65, and ML-DSA-87 test groups.
   - `SLH-DSA-sigVer-FIPS205`: Verification tests across SLH-DSA-SHA2 parameter sets.
2. **Boundary Validation & Input Sanitization**:
   - `SizeMismatchError` raised whenever public keys, secret keys, ciphertexts, or signatures fail to match exact standard byte counts.
   - Rejection of invalid algorithm parameter set identifiers.
   - Non-bytes and malformed type error handling.
3. **Hybrid Composition & Cryptographic Invariants**:
   - Key derivation using HKDF-SHA256 and HKDF-SHA384.
   - Commutative property preservation: sender and receiver recover identical 32-byte shared secrets.
   - Tamper testing on both KEM and classical components.
4. **SLH-DSA Context String Verification**:
   - Domain separation via context parameter verification.
