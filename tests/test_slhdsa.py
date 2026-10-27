"""Test SLH-DSA signature functions for pqblocks-primitives.

This test module verifies key generation, signing, verification sizes,
edge cases, and official ACVP vectors for SLH-DSA-SHA2 variants.

FIPS 205 Table 2 (bytes) — sizes verified via liboqs-python and FIPS:
    SLH-DSA-SHA2-128s: pk 32, sk 64, sig 7856
    SLH-DSA-SHA2-128f: pk 32, sk 64, sig 17088
    SLH-DSA-SHA2-192s: pk 48, sk 96, sig 16224
    SLH-DSA-SHA2-256s: pk 64, sk 128, sig 29792
"""
import os
import sys
import pytest

# Ensure src/ is on the import path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from pqblocks_primitives import SizeMismatchError

# FIPS 205 Table 2 sizes for the four Pure-SHA2 parameter sets we ship
SLHDSA_SIZES = {
    'SLH-DSA-SHA2-128s': {'pk': 32, 'sk': 64, 'sig': 7856},
    'SLH-DSA-SHA2-128f': {'pk': 32, 'sk': 64, 'sig': 17088},
    'SLH-DSA-SHA2-192s': {'pk': 48, 'sk': 96, 'sig': 16224},
    'SLH-DSA-SHA2-256s': {'pk': 64, 'sk': 128, 'sig': 29792},
}

# Mapping to liboqs names (library is authoritative for mechanism selection)
_SLHDSA_LIBOQS = {
    'SLH-DSA-SHA2-128s': 'SLH_DSA_PURE_SHA2_128S',
    'SLH-DSA-SHA2-128f': 'SLH_DSA_PURE_SHA2_128F',
    'SLH-DSA-SHA2-192s': 'SLH_DSA_PURE_SHA2_192S',
    'SLH-DSA-SHA2-256s': 'SLH_DSA_PURE_SHA2_256S',
}


@pytest.fixture(params=list(SLHDSA_SIZES.keys()))
def parameter_set(request):
    """Fixture providing SLH-DSA parameter sets."""
    return request.param


class TestSlhdsaKeygen:
    def test_slhdsa_keygen_returns_tuple(self, parameter_set):
        from pqblocks_primitives import slhdsa_keygen
        result = slhdsa_keygen(parameter_set)
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_slhdsa_keygen_correct_sizes(self, parameter_set):
        from pqblocks_primitives import slhdsa_keygen
        pk, sk = slhdsa_keygen(parameter_set)
        expected = SLHDSA_SIZES[parameter_set]
        assert len(pk) == expected['pk']
        assert len(sk) == expected['sk']

    def test_slhdsa_keygen_invalid_level(self):
        from pqblocks_primitives import slhdsa_keygen, InvalidParameterError
        with pytest.raises((InvalidParameterError, ValueError, TypeError)):
            slhdsa_keygen('INVALID-LEVEL')


class TestSlhdsaSign:
    def test_slhdsa_sign_returns_bytes(self, parameter_set):
        from pqblocks_primitives import slhdsa_keygen, slhdsa_sign
        pk, sk = slhdsa_keygen(parameter_set)
        msg = b'test message'
        sig = slhdsa_sign(msg, pk, sk, parameter_set)
        assert isinstance(sig, (bytes, bytearray))

    def test_slhdsa_sign_correct_size(self, parameter_set):
        from pqblocks_primitives import slhdsa_keygen, slhdsa_sign
        pk, sk = slhdsa_keygen(parameter_set)
        msg = b'test message'
        sig = slhdsa_sign(msg, pk, sk, parameter_set)
        expected = SLHDSA_SIZES[parameter_set]['sig']
        assert len(sig) == expected

    def test_slhdsa_sign_empty_message(self, parameter_set):
        from pqblocks_primitives import slhdsa_keygen, slhdsa_sign
        pk, sk = slhdsa_keygen(parameter_set)
        sig = slhdsa_sign(b'', pk, sk, parameter_set)
        assert len(sig) == SLHDSA_SIZES[parameter_set]['sig']


class TestSlhdsaVerify:
    def test_slhdsa_verify_accepts_valid_signature(self, parameter_set):
        from pqblocks_primitives import slhdsa_keygen, slhdsa_sign, slhdsa_verify
        pk, sk = slhdsa_keygen(parameter_set)
        msg = b'test message'
        sig = slhdsa_sign(msg, pk, sk, parameter_set)
        assert slhdsa_verify(msg, sig, pk, parameter_set) is True

    def test_slhdsa_verify_rejects_tampered_message(self, parameter_set):
        from pqblocks_primitives import slhdsa_keygen, slhdsa_sign, slhdsa_verify
        pk, sk = slhdsa_keygen(parameter_set)
        msg = b'test message'
        sig = slhdsa_sign(msg, pk, sk, parameter_set)
        tampered = msg[:-1] + bytes([msg[-1] ^ 1])
        assert slhdsa_verify(tampered, sig, pk, parameter_set) is False

    def test_slhdsa_verify_rejects_wrong_pubkey(self, parameter_set):
        from pqblocks_primitives import slhdsa_keygen, slhdsa_sign, slhdsa_verify
        pk1, sk1 = slhdsa_keygen(parameter_set)
        pk2, _ = slhdsa_keygen(parameter_set)
        msg = b'test message'
        sig = slhdsa_sign(msg, pk1, sk1, parameter_set)
        assert slhdsa_verify(msg, sig, pk2, parameter_set) is False


class TestSlhdsaEdgeCases:
    def test_invalid_pk_size(self, parameter_set):
        from pqblocks_primitives import slhdsa_verify
        bad_pk = b'\x00' * 10
        sig = b'\x00' * SLHDSA_SIZES[parameter_set]['sig']
        msg = b'test'
        with pytest.raises(Exception):
            slhdsa_verify(msg, sig, bad_pk, parameter_set)

    def test_invalid_sk_size(self, parameter_set):
        from pqblocks_primitives import slhdsa_sign
        pk = b'\x00' * SLHDSA_SIZES[parameter_set]['pk']
        bad_sk = b'\x00' * 10
        msg = b'test'
        with pytest.raises(Exception):
            slhdsa_sign(msg, pk, bad_sk, parameter_set)

    def test_invalid_sig_size(self, parameter_set):
        from pqblocks_primitives import slhdsa_verify
        pk = b'\x00' * SLHDSA_SIZES[parameter_set]['pk']
        bad_sig = b'\x00' * 10
        msg = b'test'
        with pytest.raises(Exception):
            slhdsa_verify(msg, bad_sig, pk, parameter_set)

    def test_null_bytes_handled(self, parameter_set):
        from pqblocks_primitives import slhdsa_keygen, slhdsa_sign, slhdsa_verify
        pk, sk = slhdsa_keygen(parameter_set)
        msg = b'\x00\x01\x02test\x00'
        sig = slhdsa_sign(msg, pk, sk, parameter_set)
        assert slhdsa_verify(msg, sig, pk, parameter_set) is True


class TestOfficialVectors:
    """Official ACVP vectors: SLH-DSA-sigVer-FIPS205."""

    def test_official_vectors_can_verify(self):
        """All official valid/invalid signatures verify as expected."""
        groups = []
        try:
            from .vectors_loader import load
            groups = load('SLH-DSA-sigVer-FIPS205')
        except Exception:
            try:
                import vectors_loader
                groups = vectors_loader.load('SLH-DSA-sigVer-FIPS205')
            except Exception:
                from pathlib import Path
                for sub in ('vectors/acvp', 'vectors', ''):
                    vendored = Path(__file__).parent / sub / 'SLH-DSA-sigVer-FIPS205.json'
                    if vendored.exists():
                        import json
                        with open(vendored, 'r') as f:
                            groups = json.load(f).get('testGroups', [])
                        break
        if not groups:
            pytest.skip('SLH-DSA vectors not available')
        import oqs
        from pqblocks_primitives import slhdsa_verify
        mapping = {
            'SLH-DSA-SHA2-128s': 'SLH-DSA-SHA2-128s',
            'SLH-DSA-SHA2-128f': 'SLH-DSA-SHA2-128f',
            'SLH-DSA-SHA2-192s': 'SLH-DSA-SHA2-192s',
            'SLH-DSA-SHA2-192f': 'SLH-DSA-SHA2-192f',
            'SLH-DSA-SHA2-256s': 'SLH-DSA-SHA2-256s',
            'SLH-DSA-SHA2-256f': 'SLH-DSA-SHA2-256f',
        }
        n_checked = 0
        for grp in groups:
            # liboqs PURE variants only expose external interface
            if grp.get('signatureInterface') != 'external':
                continue
            if grp.get('preHash') not in ('pure', 'none'):
                continue
            param = grp['parameterSet']
            if param not in mapping:
                continue
            level = mapping[param]
            for t in grp['tests']:
                pk = bytes.fromhex(t['pk'])
                msg = bytes.fromhex(t['message'])
                sig = bytes.fromhex(t['signature'])
                ctx_hex = t.get('context', '')
                context = bytes.fromhex(ctx_hex) if ctx_hex else b''
                try:
                    got = slhdsa_verify(msg, sig, pk, level=level, context=context)
                except SizeMismatchError:
                    # Malformed signature size - verify should return False
                    got = False
                expected = bool(t.get('testPassed'))
                assert got == expected, (
                    f'{param} tcId {t["tcId"]}: expected verify={expected}, '
                    f'got {got} (reason: {t.get("reason")})'
                )
                n_checked += 1
        assert n_checked > 0, 'No ACVP vectors checked'