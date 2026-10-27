# Cryptographic Evidence: pqblocks-primitives

## Standards & Normative References

1. **NIST FIPS 203**: Module-Lattice-Based Key-Encapsulation Mechanism Standard
   - Finalized August 2024.
   - Parameter sets: ML-KEM-512, ML-KEM-768, ML-KEM-1024.
2. **NIST FIPS 204**: Module-Lattice-Based Digital Signature Standard
   - Finalized August 2024.
   - Parameter sets: ML-DSA-44, ML-DSA-65, ML-DSA-87.
3. **NIST FIPS 205**: Stateless Hash-Based Digital Signature Standard
   - Finalized August 2024.
   - Parameter sets: SLH-DSA-SHA2 (128s, 128f, 192s, 192f, 256s, 256f).
4. **RFC 7748**: Elliptic Curves for Security (X25519).
5. **RFC 5869**: HMAC-based Extract-and-Expand Key Derivation Function (HKDF).

## Parameter Sizing Matrix

All operations strictly enforce byte lengths as specified by FIPS standards:

### ML-KEM (FIPS 203 Table 2 & 3)

| Level | Public Key (`ek`) | Secret Key (`dk`) | Ciphertext (`ct`) | Shared Secret (`ss`) |
|---|---|---|---|---|
| **ML-KEM-512** | 800 B | 1,632 B | 768 B | 32 B |
| **ML-KEM-768** | 1,184 B | 2,400 B | 1,088 B | 32 B |
| **ML-KEM-1024** | 1,568 B | 3,168 B | 1,568 B | 32 B |

### ML-DSA (FIPS 204 Table 2)

| Level | Public Key (`pk`) | Secret Key (`sk`) | Signature (`sig`) | Security Category |
|---|---|---|---|---|
| **ML-DSA-44** | 1,312 B | 2,560 B | 2,420 B | NIST Category 2 |
| **ML-DSA-65** | 1,952 B | 4,032 B | 3,309 B | NIST Category 3 |
| **ML-DSA-87** | 2,592 B | 4,896 B | 4,627 B | NIST Category 5 |

### SLH-DSA-SHA2 (FIPS 205 Table 2)

| Parameter Set | Public Key (`pk`) | Secret Key (`sk`) | Signature (`sig`) |
|---|---|---|---|
| **SLH-DSA-SHA2-128s** | 32 B | 64 B | 7,856 B |
| **SLH-DSA-SHA2-128f** | 32 B | 64 B | 17,088 B |
| **SLH-DSA-SHA2-192s** | 48 B | 96 B | 16,224 B |
| **SLH-DSA-SHA2-256s** | 64 B | 128 B | 29,792 B |
