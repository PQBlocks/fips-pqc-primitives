# pqblocks-primitives

> Production-ready integrated post-quantum cryptographic primitives (ML-KEM, ML-DSA, SLH-DSA, and hybrid schemes).

[![CI](https://github.com/PQBlocks/fips-pqc-primitives/actions/workflows/ci.yml/badge.svg)](https://github.com/PQBlocks/fips-pqc-primitives/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

---

## Overview

`pqblocks-primitives` is a unified, high-performance post-quantum cryptography library providing FIPS 203, FIPS 204, and FIPS 205 compliant algorithms alongside hybrid classical/post-quantum mechanisms.

Built on top of `liboqs` and `cryptography`, `pqblocks-primitives` exposes a clean, pythonic API with strict input validation, deterministic sizing, and fail-safe error handling.

### Standards Alignment

- **NIST FIPS 203**: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM-512, ML-KEM-768, ML-KEM-1024).
- **NIST FIPS 204**: Module-Lattice-Based Digital Signature Standard (ML-DSA-44, ML-DSA-65, ML-DSA-87).
- **NIST FIPS 205**: Stateless Hash-Based Digital Signature Standard (SLH-DSA-SHA2 variants).
- **Hybrid Key Exchange**: ML-KEM + X25519 combined with HKDF (RFC 5869) using SHA-256 or SHA-384.

> [!WARNING]
> **Non-FIPS Notice**: This library is an independent open-source wrapper and implementation. It is not certified under FIPS 140-3 and has not undergone CMVP validation. The underlying algorithms are tested against official NIST ACVP golden vectors.

---

## Installation

```bash
pip install pqblocks-primitives
```

### Dependencies & Environment

Requires Python 3.11+, `cryptography>=43.0.0`, and `liboqs-python>=0.16.0`.  
System `liboqs` shared library (`liboqs.so.9` or later) should be discoverable via standard system library paths or specified via `OQS_LIB_PATH`:

```bash
export OQS_LIB_PATH=/path/to/liboqs.so.9
export LD_LIBRARY_PATH=/path/to/lib:$LD_LIBRARY_PATH
```

---

## Quickstart

### Key Encapsulation (ML-KEM)

```python
from pqblocks_primitives import kem_keygen, kem_encaps, kem_decaps

# Generate ML-KEM-768 keypair
pk, sk = kem_keygen("768")

# Encapsulate shared secret
ct, shared_secret_sender = kem_encaps(pk, "768")

# Decapsulate shared secret
shared_secret_receiver = kem_decaps(sk, ct, "768")

assert shared_secret_sender == shared_secret_receiver
```

### Digital Signatures (ML-DSA)

```python
from pqblocks_primitives import dsa_keygen, dsa_sign, dsa_verify

# Generate ML-DSA-65 keypair
pk, sk = dsa_keygen("ML-DSA-65")

message = b"Quantum-safe transaction payload"
signature = dsa_sign(message, pk, sk, "ML-DSA-65")

# Verify signature
assert dsa_verify(message, signature, pk, "ML-DSA-65")
```

### Hybrid Key Exchange (ML-KEM-768 + X25519)

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from pqblocks_primitives import kem_keygen, hybrid_encaps, hybrid_decaps

# 1. Generate hybrid keypair
kem_pk, kem_sk = kem_keygen("768")
x_sk = x25519.X25519PrivateKey.generate()
x_pk = x_sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
x_sk_bytes = x_sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())

hybrid_pk = kem_pk + x_pk
hybrid_sk = kem_sk + x_sk_bytes

# 2. Encapsulate
encap = hybrid_encaps(hybrid_pk, "768", kdf="HKDF-SHA256")
wire_ciphertext = encap.serialize()

# 3. Decapsulate
shared_secret = hybrid_decaps(hybrid_sk, wire_ciphertext, "768", kdf="HKDF-SHA256")
assert encap.shared_secret == shared_secret
```

---

## Features

- **Standard Post-Quantum Primitives**: Complete support for NIST standardized lattice-based and hash-based algorithms.
- **Fail-Secure Boundary Checks**: Strict byte length validation (`SizeMismatchError`) on keys, ciphertexts, and signatures.
- **High Throughput**: Over 37,000 ML-KEM-768 encapsulations/sec and 18,000 ML-DSA-65 verifications/sec on modern x86_64 CPUs.
- **ACVP Validated**: 248 automated tests including regression tests against official NIST ACVP golden vectors.

---

## Documentation

- [BENCHMARKS.md](BENCHMARKS.md) - Measured latencies and throughput across all parameter sets.
- [TESTING.md](TESTING.md) - ACVP vector verification and test suite details.
- [EVIDENCE.md](EVIDENCE.md) - Parameter sets, sizes, and standards citations.
- [VERIFICATION_REPORT.md](VERIFICATION_REPORT.md) - Multi-python validation logs.
- [USE_CASES.md](USE_CASES.md) - Architectural integration recipes.
- [SECURITY_NOTES.md](SECURITY_NOTES.md) - Constant-time considerations and operational security.
- [AGENTS.md](AGENTS.md) - Automated integration instructions.
- [CHANGELOG.md](CHANGELOG.md) - Version release history.

---

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for details.
