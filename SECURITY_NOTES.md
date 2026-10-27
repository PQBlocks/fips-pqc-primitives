# Security Notes: pqblocks-primitives

## Operational Guarantees

- **Underlying Engine**: Raw lattice and hash-based operations are executed by `liboqs` C implementations.
- **Randomness**: Key generation and ephemeral encapsulation use operating system cryptographic entropy (`os.urandom` and liboqs RNG providers). Deterministic seed hooks are strictly internal and disabled in production keygen.
- **Constant-Time Operations**: Key decapsulation and comparison operations rely on constant-time C routines in liboqs to prevent timing side channels.

## Input Validation

All public APIs strictly enforce:
1. Exact expected byte lengths per FIPS 203, FIPS 204, and FIPS 205 tables. Any truncation or extra trailing bytes raises `SizeMismatchError`.
2. Parameter set validation: Passing unsupported strings raises `InvalidParameterError`.
3. Type validation: Non-bytes inputs for keys or ciphertexts raise `TypeError`.

## Non-FIPS Disclaimer

> [!NOTE]
> `pqblocks-primitives` is an open-source library wrapper and has not undergone CMVP validation under FIPS 140-3.
