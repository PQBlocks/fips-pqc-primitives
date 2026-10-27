#!/usr/bin/env python3
"""
Tests for edge cases and branch coverage in src/pqblocks_primitives/__init__.py
"""

import pytest
import pqblocks_primitives


# ─── _normalize_seed tests (lines 118-119, 121) ────────────────────────────────────────
def test_normalize_seed_invalid_hex_chars():
    """Line 118-119: seed hex string contains invalid characters"""
    # 128 chars long but contains non-hex 'g' characters
    invalid_hex = "g" * 128
    with pytest.raises(ValueError, match="hex string contains invalid characters"):
        pqblocks_primitives._normalize_seed(invalid_hex)


def test_normalize_seed_bytes_length_check():
    """Line 121: bytes seed length validation"""
    # Test too short
    with pytest.raises(ValueError, match="must be 64 bytes"):
        pqblocks_primitives._normalize_seed(b"a" * 32)

    # Test too long
    with pytest.raises(ValueError, match="must be 64 bytes"):
        pqblocks_primitives._normalize_seed(b"a" * 72)


# ─── kem_keygen_seeded path (line 174) ────────────────────────────────────────────────
def test_kem_keygen_seeded_with_seed():
    """Line 174: _kem_keygen_seeded seeded path - pk generation with seed"""
    seed = bytes(range(64))  # 64-byte seed
    pk, sk = pqblocks_primitives._kem_keygen_seeded("512", seed=seed)
    assert len(pk) == 800  # ek size for 512
    assert len(sk) == 1632  # dk size for 512


# ─── kem_encaps level inference (line 190) ────────────────────────────────────────────
def test_kem_encaps_cannot_infer_level():
    """Line 190: kem_encaps cannot infer level from pk length"""
    pk_short = b"x" * 100  # too short for any level
    with pytest.raises(pqblocks_primitives.SizeMismatchError):
        pqblocks_primitives.kem_encaps(pk_short, "512")


# ─── dsa_verify level inference (line 319) ────────────────────────────────────────────
def test_dsa_verify_level_inference_from_pk():
    """Line 319: dsa_verify level inference from pk size"""
    from pqblocks_primitives import dsa_keygen, dsa_sign, dsa_verify

    pk, sk = dsa_keygen("ML-DSA-65")
    msg = b"test"
    sig = dsa_sign(msg, pk, sk)
    # Call without level - should infer from pk size
    result = dsa_verify(msg, sig, pk)
    assert result is True


# ─── slhdsa_verify level inference (line 377-378) ────────────────────────────────────
def test_slhdsa_verify_level_inference_from_pk():
    """Line 377-378: slhdsa_verify level inference from pk size"""
    from pqblocks_primitives import slhdsa_keygen, slhdsa_sign, slhdsa_verify

    pk, sk = slhdsa_keygen("SLH-DSA-SHA2-128s")
    msg = b"test"
    sig = slhdsa_sign(msg, pk, sk)
    # Call without level - should infer from pk size
    result = slhdsa_verify(msg, sig, pk)
    assert result is True


# ─── hybrid_encaps size mismatch (line 498, 734) ───────────────────────────────────────
def test_hybrid_encaps_size_mismatch():
    """Line 498, 734: hybrid_encaps size mismatch check"""
    from pqblocks_primitives import hybrid_encaps

    pk = b"x" * 100  # wrong size
    with pytest.raises(pqblocks_primitives.SizeMismatchError):
        hybrid_encaps(pk, "512")


# ─── slhdsa_sign level inference (line 501-506) ────────────────────────────────────────
def test_slhdsa_sign_level_inference_from_keys():
    """Line 501-506: slhdsa_sign level inference from key sizes"""
    from pqblocks_primitives import slhdsa_keygen, slhdsa_sign

    pk, sk = slhdsa_keygen("SLH-DSA-SHA2-128s")
    # Call without explicit level - should infer from key sizes
    sig = slhdsa_sign(b"test", pk, sk)
    assert len(sig) == 7856  # SLH-DSA-SHA2-128s sig size


# ─── slhdsa_verify level inference (line 559-564) ───────────────────────────────────────
def test_slhdsa_verify_level_inference_from_pk():
    """Line 559-564: slhdsa_verify level inference from pk size"""
    from pqblocks_primitives import slhdsa_keygen, slhdsa_sign, slhdsa_verify

    pk, sk = slhdsa_keygen("SLH-DSA-SHA2-128s")
    msg = b"test"
    sig = slhdsa_sign(msg, pk, sk)
    # Call without level - should infer from pk size
    result = slhdsa_verify(msg, sig, pk)
    assert result is True


# ─── Additional tests for other uncovered branches ────────────────────────────────────
def test_dsa_sign_level_inference_from_keys():
    """Line 322-327: dsa_sign level inference from key sizes"""
    from pqblocks_primitives import dsa_keygen, dsa_sign

    pk, sk = dsa_keygen("ML-DSA-65")
    # Call without explicit level - should infer from key sizes
    sig = dsa_sign(b"test", pk, sk)
    assert len(sig) == 3309


def test_dsa_sign_invalid_sk_size_raises():
    """Line 322-327: dsa_sign invalid sk size raises"""
    from pqblocks_primitives import dsa_sign

    pk = b"x" * 1952  # ML-DSA-87 pk size
    sk = b"x" * 100  # wrong size
    with pytest.raises(pqblocks_primitives.SizeMismatchError):
        dsa_sign(b"msg", pk, sk)


def test_dsa_sign_invalid_pk_size_raises():
    """Line 322-327: dsa_sign invalid pk size raises"""
    from pqblocks_primitives import dsa_sign

    pk = b"x" * 100  # wrong size
    sk = b"x" * 4032  # ML-DSA-87 sk size
    with pytest.raises(pqblocks_primitives.SizeMismatchError):
        dsa_sign(b"msg", pk, sk)


def test_dsa_verify_invalid_level_explicit():
    """Line 310: dsa_verify invalid level explicit"""
    from pqblocks_primitives import dsa_verify

    pk = b"x" * 100  # pk size matches no ML-DSA level
    with pytest.raises(pqblocks_primitives.SizeMismatchError):
        dsa_verify(b"msg", b"sig", pk, "INVALID-LEVEL")


def test_dsa_verify_level_inference_from_pk():
    """Line 375-380: dsa_verify level inference from pk size"""
    from pqblocks_primitives import dsa_keygen, dsa_sign, dsa_verify

    pk, sk = dsa_keygen("ML-DSA-65")
    msg = b"test"
    sig = dsa_sign(msg, pk, sk)
    # Call without level - should infer from pk size
    result = dsa_verify(msg, sig, pk)
    assert result is True


def test_slhdsa_sign_level_inference_from_keys_alt():
    """Line 501-506: slhdsa_sign level inference from key sizes (alt)"""
    from pqblocks_primitives import slhdsa_keygen, slhdsa_sign

    pk, sk = slhdsa_keygen("SLH-DSA-SHA2-128s")
    # Call without explicit level - should infer from key sizes
    sig = slhdsa_sign(b"test", pk, sk)
    assert len(sig) == 7856


def test_slhdsa_verify_level_inference_from_pk_alt():
    """Line 559-564: slhdsa_verify level inference from pk size"""
    from pqblocks_primitives import slhdsa_keygen, slhdsa_sign, slhdsa_verify

    pk, sk = slhdsa_keygen("SLH-DSA-SHA2-128s")
    msg = b"test"
    sig = slhdsa_sign(msg, pk, sk)
    # Call without level - should infer from pk size
    result = slhdsa_verify(msg, sig, pk)
    assert result is True


def test_slhdsa_verify_context_mismatch_raises():
    """Line 559-564: slhdsa_verify level inference from pk size + context branch"""
    from pqblocks_primitives import slhdsa_keygen, slhdsa_sign, slhdsa_verify

    pk, sk = slhdsa_keygen("SLH-DSA-SHA2-128s")
    msg = b"test"
    sig = slhdsa_sign(msg, pk, sk, context=b"context1")
    # Verify with different context should fail
    result = slhdsa_verify(msg, sig, pk, context=b"context2")
    assert result is False


def test_hybrid_encaps_size_mismatch_alt():
    """Line 734: hybrid_encaps size mismatch check (alt)"""
    from pqblocks_primitives import hybrid_encaps

    pk = b"x" * 100  # wrong size
    with pytest.raises(pqblocks_primitives.SizeMismatchError):
        hybrid_encaps(pk, "512")


def test_hybrid_decaps_type_error_secret_key():
    """Line 811: hybrid_decaps type check for secret_key"""
    from pqblocks_primitives import hybrid_decaps

    with pytest.raises(TypeError, match="secret_key must be bytes"):
        hybrid_decaps("not bytes", b"ct", "512")


def test_hybrid_decaps_type_error_ct():
    """Line 813: hybrid_decaps type check for ct"""
    from pqblocks_primitives import hybrid_decaps

    with pytest.raises(TypeError, match="ct must be bytes"):
        hybrid_decaps(b"sk", "not bytes", "512")