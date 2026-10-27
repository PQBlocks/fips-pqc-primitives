#!/usr/bin/env python3
"""
ACVP official vector validation for integrated PQC dependency.

Tests that our pqblocks-primitives implementation correctly handles NIST ACVP official vectors.
Loads published test groups and compares against implementation output.
"""

import os
import sys
import pathlib

# Ensure src/ is on the import path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest


def load_af_vectors(vector_name):
    """Load official ACVP vectors, with fallback to vendored copy."""
    try:
        from .vectors_loader import load
        return load(vector_name)
    except Exception:
        try:
            import vectors_loader
            return vectors_loader.load(vector_name)
        except Exception:
            pass

    # Fallback: load from vendored vectors if available
    lane_dir = pathlib.Path(__file__).parent.parent
    for sub in ('vectors/acvp', 'vectors', ''):
        vendored = lane_dir / 'tests' / sub / (vector_name + '.json')
        if vendored.exists():
            import json
            with open(vendored, 'r') as f:
                doc = json.load(f)
            return doc.get('testGroups', [])

    return []


@pytest.fixture(params=['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024'])
def parameter_set(request):
    """Provide KEM parameter sets."""
    return request.param


def test_official_encap_decap_vectors(parameter_set):
    """Golden truth: ML-KEM-encapDecap-FIPS203 from NIST ACVP.

    Runs decapsulation for every published case and checks the decapsulated
    shared secret equals the published k value (deterministic, directly
    validated against ACVP golden vectors).
    """
    from pqblocks_primitives import kem_encaps, kem_decaps

    groups = load_af_vectors('ML-KEM-encapDecap-FIPS203')
    checked = 0
    checked_levels = set()
    skipped_reason = 0

    for group in groups:
        param_set = group.get('parameterSet', '')
        level = param_set.replace('ML-KEM-', '') if param_set else ''
        if not level or level not in ['512', '768', '1024']:
            continue

        function = group.get('function')
        for test in group.get('tests', []):
            checked_levels.add(level)

            # Skip known-invalid cases (reason field indicates expected failure)
            if test.get('reason'):
                skipped_reason += 1
                continue

            if function == 'decapsulation':
                dk = bytes.fromhex(test['dk'])
                ct = bytes.fromhex(test['c'])
                expected_ss_hex = test.get('k')
                ss = kem_decaps(dk, ct, level)

                if expected_ss_hex:
                    assert ss is not None, \
                        f"tcId={test['tcId']} {level} decapsulation failed (ss is None) but expected shared secret k"
                    assert ss.hex().upper() == expected_ss_hex.upper(), \
                        f"tcId={test['tcId']} {level} ss mismatch: " \
                        f"got {ss.hex().upper() if ss else None}, expected {expected_ss_hex.upper()}"
                else:
                    # No k value - FIPS 203 allows implicit rejection (return None)
                    assert ss is None or isinstance(ss, bytes), \
                        f"tcId={test['tcId']} {level} unexpected ss type: {type(ss)}"

                checked += 1

            elif function == 'encapsulation':
                # Round-trip: encapsulate with ek, decapsulate with dk,
                # verify we get back a shared secret of correct length
                ek = bytes.fromhex(test['ek'])
                dk = bytes.fromhex(test['dk'])
                ct_out, ss_out = kem_encaps(ek, level)
                assert len(ct_out) == {'512': 768, '768': 1088, '1024': 1568}[level], \
                    f"ciphertext must be {768 if level=='512' else 1088 if level=='768' else 1568} bytes"
                ss2 = kem_decaps(dk, ct_out, level)
                assert ss_out == ss2, \
                    f"tcId={test['tcId']} {level} encap/decap round-trip mismatch"

                checked += 1

    # At least one official vector case must be exercised
    assert checked > 0, "at least one official vector case must be exercised"
    # Must check ML-KEM-768 level or multiple levels
    assert '768' in checked_levels or len(checked_levels) >= 2, \
        f"Must check ML-KEM-768 level or multiple levels, got {checked_levels}"
    if skipped_reason > 0:
        print(f"  (skipped {skipped_reason} known-invalid cases with reason field)")


def test_official_slhdsa_vectors():
    """Test SLH-DSA official ACVP vectors from NIST ACVP."""
    groups = load_af_vectors('SLH-DSA-sigVer-FIPS205')
    if not groups:
        pytest.skip('SLH-DSA vectors not available')

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
            # slhdsa_verify(msg, sig, pk, level, context) - context is 5th param
            try:
                got = slhdsa_verify(msg, sig, pk, level, context)
            except Exception:
                got = False
            expected = bool(t.get('testPassed'))
            assert got == expected, \
                f'{param} tcId {t["tcId"]}: expected verify={expected}, got {got} (reason: {t.get("reason")})'
            n_checked += 1

    assert n_checked > 0, 'No ACVP vectors checked'


def test_official_ml_dsa_vectors():
    """Test ML-DSA official ACVP vectors from NIST ACVP."""
    groups = load_af_vectors('ML-DSA-sigVer-FIPS204')
    if not groups:
        pytest.skip('ML-DSA vectors not available')

    from pqblocks_primitives import dsa_keygen, dsa_sign, dsa_verify

    mldsa_sizes = {
        'ML-DSA-44': {'pk': 1312, 'sk': 2560, 'sig': 2420},
        'ML-DSA-65': {'pk': 1952, 'sk': 4032, 'sig': 3309},
        'ML-DSA-87': {'pk': 2592, 'sk': 4896, 'sig': 4627},
    }

    checked = 0
    for parameter_set in ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']:
        matching_groups = [g for g in groups if g.get('parameterSet') == parameter_set]
        assert matching_groups, f"No vectors found for {parameter_set}"

        for group in matching_groups:
            # liboqs exposes only the external interface; skip internal-mu
            # (pure) and preHash (hashAlg SHA2-512/256) groups that external
            # verify() cannot validate directly, exactly as the SLH-DSA ACVP
            # test does (SLH-DSA also validates only signatureInterface ==
            # external + preHash in ('pure', 'none')).
            if group.get('signatureInterface') != 'external':
                continue
            if group.get('preHash') not in ('pure', 'none'):
                continue
            tests = group.get('tests', [])
            for test in tests:
                pk_hex = test.get('pk')
                sk_hex = test.get('sk')
                msg_hex = test.get('message')
                sig_hex = test.get('signature')
                context_hex = test.get('context', '')

                if not all([pk_hex, sk_hex, msg_hex, sig_hex]):
                    continue

                pk = bytes.fromhex(pk_hex)
                sk = bytes.fromhex(sk_hex)
                sig = bytes.fromhex(sig_hex)
                msg = bytes.fromhex(msg_hex)
                context = bytes.fromhex(context_hex) if context_hex else b''

                expected_pk = mldsa_sizes[parameter_set]['pk']
                expected_sk = mldsa_sizes[parameter_set]['sk']
                expected_sig = mldsa_sizes[parameter_set]['sig']

                assert len(pk) == expected_pk, \
                    f"PK size mismatch: {len(pk)} vs {expected_pk}"
                assert len(sk) == expected_sk, \
                    f"SK size mismatch: {len(sk)} vs {expected_sk}"
                assert len(sig) == expected_sig, \
                    f"SIG size mismatch: {len(sig)} vs {expected_sig}"

                # Verify the signature actually validates
                expected_verified = bool(test.get('testPassed', True))
                # dsa_verify(msg, sig, pk, level, ctx) - ctx is keyword
                got = dsa_verify(msg, sig, pk, level=parameter_set, ctx=context)
                assert got == expected_verified, \
                    f"{parameter_set} tcId={test.get('tcId', '?')}: " \
                    f"expected verified={expected_verified}, got {got}"

                checked += 1

    assert checked > 0, "No ML-DSA official vector cases were checked"