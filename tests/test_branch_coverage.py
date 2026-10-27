#!/usr/bin/env python3
"""
Tests targeting branch coverage in src/pqblocks_primitives/__init__.py
"""

import pytest
import pqblocks_primitives


# Line 121: 128-char hex string that decodes to fewer than 64 bytes
# (whitespace is skipped by bytes.fromhex, so this passes len!=128 but decodes short)
def test_normalize_seed_hex_decodes_short():
    """Line 121: hex string passes 128-char check but decodes to <64 bytes"""
    # 63 bytes of hex (126 chars) + 2 spaces = 128 chars total
    hex_short_ws = "61" * 63 + "  "
    assert len(hex_short_ws) == 128
    with pytest.raises(ValueError, match="must be 64 bytes"):
        pqblocks_primitives._normalize_seed(hex_short_ws)


# Line 174: _kem_keygen_seeded with seed=None (falls through to generate_keypair)
def test_kem_keygen_seeded_no_seed():
    """Line 174: _kem_keygen_seeded with seed=None exercises the else path"""
    pk, sk = pqblocks_primitives._kem_keygen_seeded("512", seed=None)
    assert len(pk) == 800
    assert len(sk) == 1632


# Line 190: kem_encaps with level=None and an uninferrable pk length
def test_kem_encaps_level_none_uninferrable():
    """Line 190: kem_encaps(level=None) with wrong pk length raises"""
    pk = b"\x00" * 100  # matches no _KEM_SIZES ek
    with pytest.raises(pqblocks_primitives.SizeMismatchError, match="cannot infer ML-KEM level"):
        pqblocks_primitives.kem_encaps(pk, None)


# Lines 319, 322-327: dsa_sign with invalid level => inference loop + error
def test_dsa_sign_invalid_level_inference_fails():
    """Lines 319, 322-327: dsa_sign invalid level triggers inference, then raises"""
    pk = b"\x00" * 100  # matches no ML-DSA level
    sk = b"\x00" * 100
    with pytest.raises(pqblocks_primitives.SizeMismatchError, match="cannot infer ML-DSA level"):
        pqblocks_primitives.dsa_sign(b"msg", pk, sk, "INVALID-LEVEL")


# Lines 377-378, 380: dsa_verify with explicit invalid level
def test_dsa_verify_invalid_level_explicit_raises():
    """Lines 377-378, 380: dsa_verify explicit invalid level => inference fails"""
    pk = b"\x00" * 100  # matches no ML-DSA pk size
    with pytest.raises(pqblocks_primitives.SizeMismatchError, match="cannot infer ML-DSA level"):
        pqblocks_primitives.dsa_verify(b"msg", b"sig", pk, "INVALID-LEVEL")


# Lines 498, 501-506: slhdsa_sign invalid level => inference loop + error
def test_slhdsa_sign_invalid_level_inference_fails():
    """Lines 498, 501-506: slhdsa_sign invalid level triggers inference, then raises"""
    pk = b"\x00" * 100  # matches no SLH-DSA pk size
    sk = b"\x00" * 100
    with pytest.raises(pqblocks_primitives.SizeMismatchError, match="cannot infer SLH-DSA level"):
        pqblocks_primitives.slhdsa_sign(b"msg", pk, sk, "INVALID-LEVEL")


# Lines 561-562: slhdsa_verify level inference from pk size (invalid level)
def test_slhdsa_verify_invalid_level_explicit_raises():
    """Lines 561-562: slhdsa_verify invalid level => pk-size inference fails"""
    pk = b"\x00" * 100  # matches no SLH-DSA pk size
    with pytest.raises(pqblocks_primitives.SizeMismatchError, match="cannot infer SLH-DSA level"):
        pqblocks_primitives.slhdsa_verify(b"msg", b"sig", pk, "INVALID-LEVEL")


# Line 734: hybrid_encaps type check for non-bytes public_key
def test_hybrid_encaps_non_bytes_pk_type_error():
    """Line 734: hybrid_encaps type check for non-bytes public_key"""
    with pytest.raises(TypeError, match="public_key must be bytes"):
        pqblocks_primitives.hybrid_encaps("not bytes", "512")


# Additional tests for other uncovered branches ────────────────────────────────────
def test_kem_keygen_seeded_with_seed():
    """Line 174: _kem_keygen_seeded seeded path - pk generation with seed"""
    seed = bytes(range(64))  # 64-byte seed
    pk, sk = pqblocks_primitives._kem_keygen_seeded("512", seed=seed)
    assert len(pk) == 800  # ek size for 512
    assert len(sk) == 1632  # dk size for 512


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


def test_hybrid_encaps_size_mismatch():
    """Line 734: hybrid_encaps size mismatch check"""
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