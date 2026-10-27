# Agents Guide: pqblocks-primitives

This guide provides automated test and integration instructions for `pqblocks-primitives`.

## Validation Commands

```bash
# Ensure liboqs paths are exported
export OQS_LIB_PATH=/path/to/liboqs.so.9
export LD_LIBRARY_PATH=/path/to/lib:$LD_LIBRARY_PATH

# Run test suite
pytest -v

# Check coverage
pytest --cov=pqblocks_primitives --cov-fail-under=90

# Run examples
python examples/quickstart.py
python examples/02_hybrid_kem_and_slhdsa.py
```

## Public API Symbols

Exports from `pqblocks_primitives`:
- `kem_keygen`, `kem_encaps`, `kem_decaps`
- `dsa_keygen`, `dsa_sign`, `dsa_verify`
- `slhdsa_keygen`, `slhdsa_sign`, `slhdsa_verify`
- `hybrid_encaps`, `hybrid_decaps`, `HybridEncapsulation`
- `PQCError`, `SizeMismatchError`, `InvalidParameterError`
