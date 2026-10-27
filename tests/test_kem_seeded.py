"""
ML-KEM seeded key generation determinism (test-only hook).

The deterministic keygen hook is deliberately NOT public API: key material
must come from the OS CSPRNG. These tests exercise the module-private
`_kem_keygen_seeded` so the seeded path (used by ACVP keyGen vectors) stays
covered without exposing caller-controlled randomness to users.

Slice contract: kem_keygen(level) accepts a `seed` argument.
Seed makes key generation deterministic across calls; acvp keyGen group z+d
maps to seed bytes.
"""

import pytest
import pqblocks_primitives

# module-private deterministic hook — tests only
_kem_keygen_seeded = pqblocks_primitives._kem_keygen_seeded

KEM_LEVELS = ["512", "768", "1024"]


def test_kem_keygen_seed_bytes_deterministic():
    seed = bytes(range(64))
    pk1, sk1 = _kem_keygen_seeded("512", seed=seed)
    pk2, sk2 = _kem_keygen_seeded("512", seed=seed)
    assert pk1 == pk2
    assert sk1 == sk2


def test_kem_keygen_seed_hex_string_deterministic():
    seed_hex = "00" * 64
    pk1, sk1 = _kem_keygen_seeded("512", seed=seed_hex)
    pk2, sk2 = _kem_keygen_seeded("512", seed=seed_hex)
    assert pk1 == pk2
    assert sk1 == sk2


def test_kem_keygen_seed_bytes_vs_hex_equivalent():
    seed_bytes = bytes.fromhex("aa" * 64)
    seed_hex = "aa" * 64
    pk_b, sk_b = _kem_keygen_seeded("512", seed=seed_bytes)
    pk_h, sk_h = _kem_keygen_seeded("512", seed=seed_hex)
    assert pk_b == pk_h
    assert sk_b == sk_h


@pytest.mark.parametrize("level", KEM_LEVELS)
def test_kem_keygen_seed_different_levels_deterministic(level):
    seed = bytes(range(64))
    pk1, sk1 = _kem_keygen_seeded(level, seed=seed)
    pk2, sk2 = _kem_keygen_seeded(level, seed=seed)
    assert pk1 == pk2
    assert sk1 == sk2


def test_kem_keygen_seed_differs_from_random():
    seed = bytes([0x0] * 64)
    pk_seed, sk_seed = _kem_keygen_seeded("512", seed=seed)
    pk_rand, sk_rand = pqblocks_primitives.kem_keygen("512")
    assert pk_seed != pk_rand
    assert sk_seed != sk_rand


def test_kem_keygen_different_seeds_produce_different_keys():
    seed1 = bytes.fromhex("00" * 64)
    seed2 = bytes.fromhex("01" * 64)
    pk1, sk1 = _kem_keygen_seeded("512", seed=seed1)
    pk2, sk2 = _kem_keygen_seeded("512", seed=seed2)
    assert pk1 != pk2
    assert sk1 != sk2


def test_kem_keygen_seed_invalid_type_raises():
    with pytest.raises(TypeError):
        _kem_keygen_seeded("512", seed=123)


def test_kem_keygen_seed_invalid_length_raises():
    with pytest.raises(ValueError):
        _kem_keygen_seeded("512", seed=b"\x00" * 16)


def test_kem_seed_hex_odd_length_raises():
    with pytest.raises(Exception):
        _kem_keygen_seeded("512", seed="abc")  # odd length hex


def test_kem_seed_roundtrip_with_encap_decap():
    seed = bytes.fromhex("deadbeef" * 16)  # 16 * 4 bytes = exactly 64 bytes
    pk, sk = _kem_keygen_seeded("512", seed=seed)
    ct, ss = pqblocks_primitives.kem_encaps(pk, "512")
    ss2 = pqblocks_primitives.kem_decaps(sk, ct, "512")
    assert ss == ss2
    assert len(pk) == 800
    assert len(sk) == 1632
    assert len(ct) == 768
    assert len(ss) == 32


def test_kem_keygen_public_api_rejects_seed_argument():
    """The public API must not expose caller-controlled key randomness."""
    with pytest.raises(TypeError):
        pqblocks_primitives.kem_keygen("512", seed=b"\x00" * 64)


def test_kem_keygen_seed_spec_example_size():
    seed_hex = "a3896e30892230a6c1dff667f8caee759ff84a08e3462ae484fcbca9971d7959cdc6c5ec65f10a5a24b5145aac863232ee3b2229ca3a6c4b9c8a2dafc315d9d4"
    pk, sk = _kem_keygen_seeded("512", seed=seed_hex)
    assert len(pk) == 800
    assert len(sk) == 1632
