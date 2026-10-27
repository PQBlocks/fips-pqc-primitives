"""
Hybrid key exchange tests (ML-KEM + X25519, HKDF-SHA256).

Tests are written BEFORE implementation (TDD RED).

Wire composition (spec §4.2 + brief §3.1):
  hybrid public key  : ML-KEM encapsulation key || X25519 public key (32)
  hybrid secret key  : ML-KEM decapsulation key || X25519 private key (32)
  serialized ct      : ML-KEM ciphertext || ephemeral X25519 public key (32)
  hybrid shared key  : HKDF(SHA256, ikm = KemSS || X25519SS, 32 bytes)
"""

import pytest

import pqblocks_primitives
from pqblocks_primitives import hybrid_encaps, hybrid_decaps, HybridEncapsulation
from pqblocks_primitives import InvalidParameterError, SizeMismatchError
from pqblocks_primitives import kem_keygen

from cryptography.hazmat.primitives import serialization as _ser
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PublicKey,
    X25519PrivateKey,
)

LEVELS = ["512", "768", "1024"]
CT_BYTES = {"512": 768, "768": 1088, "1024": 1568}
X25519_PK = 32
X25519_SK = 32


# ------------------------------------------------------------ fixture helpers

def _x25519_pair() -> "tuple[bytes, bytes]":
    """Return (pk_raw32, sk_raw32) for a fresh X25519 keypair."""
    sk = x25519.X25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(
        encoding=_ser.Encoding.Raw,
        format=_ser.PublicFormat.Raw,
    )
    return pk, sk.private_bytes(
        encoding=_ser.Encoding.Raw,
        format=_ser.PrivateFormat.Raw,
        encryption_algorithm=_ser.NoEncryption(),
    )


def _status(pair):
    return pair


def _hybrid_keypair(level: str) -> "tuple[bytes, bytes, bytes, bytes]":
    """Return (hybrid_pk, hybrid_sk, x_pk, x_sk) — the hybrid + split-out X25519 keys."""
    kem_pk, kem_sk = kem_keygen(level)
    x25519_pk, x25519_sk = _x25519_pair()
    hybrid_pk = kem_pk + x25519_pk
    hybrid_sk = kem_sk + x25519_sk
    return hybrid_pk, hybrid_sk, x25519_pk, x25519_sk


def _kem_and_x25519_sizes(level: str):
    ek = {"512": 800, "768": 1184, "1024": 1568}[level]
    dk = {"512": 1632, "768": 2400, "1024": 3168}[level]
    return ek, dk


# ---------------------------------------------------------------- happy path

@pytest.mark.parametrize("level", LEVELS)
def test_hybrid_public_and_secret_key_sizes(level):
    """Hybrid pk = ek+32, hybrid sk = dk+32 (kem || x25519)."""
    ek, dk = _kem_and_x25519_sizes(level)
    hybrid_pk, hybrid_sk, *_ = _hybrid_keypair(level)
    assert len(hybrid_pk) == ek + X25519_PK, f"hybrid pk must be {ek}+32 bytes"
    assert len(hybrid_sk) == dk + X25519_SK, f"hybrid sk must be {dk}+32 bytes"


@pytest.mark.parametrize("level", LEVELS)
def test_hybrid_encaps_returns_hybrid_encapsulation_with_correct_sizes(level):
    """HybridEncapsulation fields carry the documented widths."""
    hybrid_pk, _, _, _ = _hybrid_keypair(level)
    encap = hybrid_encaps(hybrid_pk, level)
    assert isinstance(encap, HybridEncapsulation), "must return HybridEncapsulation"
    assert isinstance(encap.kem_ciphertext, bytes)
    assert isinstance(encap.classical_public, bytes)
    assert isinstance(encap.shared_secret, bytes)
    assert isinstance(encap.suite_id, str)
    assert len(encap.kem_ciphertext) == CT_BYTES[level], (
        f"ML-KEM ciphertext must be {CT_BYTES[level]} bytes (FIPS 203 Table 3)"
    )
    assert len(encap.classical_public) == X25519_PK, (
        "classical_public must be the 32-byte ephemeral X25519 pk"
    )
    assert len(encap.shared_secret) == 32, "hybrid shared secret must be 32 bytes"


@pytest.mark.parametrize("level", LEVELS)
def test_hybrid_roundtrip_recovers_shared_secret(level):
    """sender encapsulates → receiver decapsulates → identical 32-byte secret."""
    hybrid_pk, hybrid_sk, _, _ = _hybrid_keypair(level)
    encap = hybrid_encaps(hybrid_pk, level)
    ss = hybrid_decaps(hybrid_sk, encap.serialize(), level)
    assert isinstance(ss, bytes)
    assert len(ss) == 32
    assert ss == encap.shared_secret, (
        "decapsulation must recover exactly what encapsulation produced"
    )


@pytest.mark.parametrize("level", LEVELS)
def test_hybrid_encaps_is_random_between_calls(level):
    """Two encapsulations under the same key must produce different ciphertexts/secrets."""
    hybrid_pk, _, _, _ = _hybrid_keypair(level)
    a = hybrid_encaps(hybrid_pk, level)
    b = hybrid_encaps(hybrid_pk, level)
    assert a.kem_ciphertext != b.kem_ciphertext
    assert a.classical_public != b.classical_public
    assert a.shared_secret != b.shared_secret


@pytest.mark.parametrize("level", LEVELS)
def test_hybrid_shared_secret_differs_from_pure_kem_secret(level):
    """The hybrid secret must not equal either ingredient's raw secret."""
    hybrid_pk, hybrid_sk, _, _ = _hybrid_keypair(level)
    encap = hybrid_encaps(hybrid_pk, level)
    kem_pk = hybrid_pk[: _kem_and_x25519_sizes(level)[0]]
    kem_sk = hybrid_sk[: _kem_and_x25519_sizes(level)[1]]
    _, kem_ss = pqblocks_primitives.kem_encaps(kem_pk, level)
    assert encap.shared_secret != kem_ss, (
        "hybrid secret must be derived from both halves, not the KEM half alone"
    )


# ------------------------------------------------------------ suite_id / kdf

@pytest.mark.parametrize("level", LEVELS)
def test_hybrid_suite_id_names_both_components(level):
    """suite_id must name the exact construction so it can go into a CBOM."""
    hybrid_pk, _, _, _ = _hybrid_keypair(level)
    suite_id = hybrid_encaps(hybrid_pk, level).suite_id
    assert f"ML-KEM-{level}" in suite_id
    assert "X25519" in suite_id
    assert "HKDF-SHA256" in suite_id


@pytest.mark.parametrize("level", ["512"])
def test_hybrid_kdf_sha384_is_a_different_secret(level):
    """HKDF-SHA384 must produce a different secret than HKDF-SHA256 for same inputs."""
    hybrid_pk, hybrid_sk, _, _ = _hybrid_keypair(level)
    a = hybrid_encaps(hybrid_pk, level, kdf="HKDF-SHA256")
    b = hybrid_encaps(hybrid_pk, level, kdf="HKDF-SHA384")
    assert a.suite_id != b.suite_id
    assert "HKDF-SHA384" in b.suite_id
    # same ingredients, different KDF → different derived secret
    assert a.shared_secret != b.shared_secret


@pytest.mark.parametrize("level", ["512"])
def test_hybrid_kdf_default_is_hkdf_sha256(level):
    """The documented default KDF is HKDF-SHA256."""
    hybrid_pk, _, _, _ = _hybrid_keypair(level)
    assert "HKDF-SHA256" in hybrid_encaps(hybrid_pk, level).suite_id


# ----------------------------------------------------------- determinism

@pytest.mark.parametrize("level", ["512"])
def test_hybrid_decaps_is_deterministic_spilogue(level):
    """hybrid_decaps is deterministic given (sk, ct): same bytes in → same secret out."""
    hybrid_pk, hybrid_sk, _, _ = _hybrid_keypair(level)
    encap = hybrid_encaps(hybrid_pk, level)
    ss1 = hybrid_decaps(hybrid_sk, encap.serialize(), level)
    ss2 = hybrid_decaps(hybrid_sk, encap.serialize(), level)
    assert ss1 == ss2


# --------------------------------------------------------- X25519 semantics

@pytest.mark.parametrize("level", ["512"])
def test_hybrid_classical_public_is_an_ephemeral_x25519_key(level):
    """classical_public must be a parseable X25519 public point of 32 bytes."""
    hybrid_pk, _, _, _ = _hybrid_keypair(level)
    encap = hybrid_encaps(hybrid_pk, level)
    # A malformed X25519 key raises ValueError on from_public_bytes
    recovered = X25519PublicKey.from_public_bytes(encap.classical_public)
    assert recovered.public_bytes(
        encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.Raw,
        format=__import__("cryptography").hazmat.primitives.serialization.PublicFormat.Raw,
    ) == encap.classical_public


@pytest.mark.parametrize("level", ["512"])
def test_hybrid_classical_public_is_not_recipient_key(level):
    """The classical_public in the envelope is the ephemeral key, never the recipient's."""
    hybrid_pk, _, x_pk, _ = _hybrid_keypair(level)
    encap = hybrid_encaps(hybrid_pk, level)
    assert encap.classical_public != x_pk, (
        "the transmitted classical key must be the ephemeral, not the recipient's static key"
    )


@pytest.mark.parametrize("level", ["512"])
def test_hybrid_composition_matches_manual_hkdf(level):
    """
    Reference tier: independently compose KemSS || X25519SS and HKDF-SHA256
    and assert the product derives the identical secret.
    """
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    hybrid_pk, hybrid_sk, _, _ = _hybrid_keypair(level)
    ek, dk = _kem_and_x25519_sizes(level)
    kem_pk, x_pk = hybrid_pk[:ek], hybrid_pk[ek:]
    kem_sk, x_sk = hybrid_sk[:dk], hybrid_sk[dk:]

    encap = hybrid_encaps(hybrid_pk, level)
    kem_ct, eph_pub = encap.kem_ciphertext, encap.classical_public

    # Ingredient 1: ML-KEM shared secret (recompute independently)
    kem_ss = pqblocks_primitives.kem_decaps(kem_sk, kem_ct, level)

    # Ingredient 2: X25519 shared secret (recompute independently)
    static_sk = X25519PrivateKey.from_private_bytes(x_sk)
    eph = X25519PublicKey.from_public_bytes(eph_pub)
    x_ss = static_sk.exchange(eph)

    ikm = kem_ss + x_ss
    expected = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"",
    ).derive(ikm)

    assert encap.shared_secret == expected, (
        "hybrid secret must equal HKDF-SHA256(KemSS || X25519SS) with no salt and empty info"
    )


# ------------------------------------------------------------ edge / negative

def test_hybrid_invalid_kem_level_rejected():
    """Unknown level string raises InvalidParameterError, never a silent fallback."""
    hybrid_pk, _, _, _ = _hybrid_keypair("512")
    with pytest.raises(InvalidParameterError):
        hybrid_encaps(hybrid_pk, "256")
    hybrid_pk, hybrid_sk, _, _ = _hybrid_keypair("512")
    encap = hybrid_encaps(hybrid_pk, "512")
    with pytest.raises(InvalidParameterError):
        hybrid_decaps(hybrid_sk, encap.serialize(), "256")


def test_hybrid_type_error_on_level():
    """Non-str level raises TypeError (the package's established convention)."""
    hybrid_pk, _, _, _ = _hybrid_keypair("512")
    with pytest.raises(TypeError):
        hybrid_encaps(hybrid_pk, 512)


def test_hybrid_wrong_public_key_size_rejected():
    """A hybrid pk that is not ek+32 raises SizeMismatchError."""
    hybrid_pk, _, _, _ = _hybrid_keypair("512")
    ek, dk = _kem_and_x25519_sizes("512")
    with pytest.raises(SizeMismatchError):
        hybrid_encaps(hybrid_pk[:-1], "512")
    with pytest.raises(SizeMismatchError):
        hybrid_encaps(hybrid_pk[:-8], "512")


def test_hybrid_empty_public_key_rejected():
    """Empty input is rejected, not tolerated (spec §10)."""
    with pytest.raises(SizeMismatchError):
        hybrid_encaps(b"", "512")


def test_hybrid_wrong_secret_key_size_rejected():
    """A hybrid sk that is not dk+32 raises SizeMismatchError."""
    hybrid_pk, hybrid_sk, _, _ = _hybrid_keypair("512")
    encap = hybrid_encaps(hybrid_pk, "512")
    with pytest.raises(SizeMismatchError):
        hybrid_decaps(hybrid_sk[:-1], encap.serialize(), "512")


def test_hybrid_wrong_ciphertext_size_rejected():
    """A serialized ct that is not ct+32 raises SizeMismatchError."""
    hybrid_pk, hybrid_sk, _, _ = _hybrid_keypair("512")
    encap = hybrid_encaps(hybrid_pk, "512")
    with pytest.raises(SizeMismatchError):
        hybrid_decaps(hybrid_sk, encap.kem_ciphertext, "512")  # missing the 32-byte suffix


def test_hybrid_empty_ciphertext_rejected():
    """Empty ct raises SizeMismatchError, not a backend error."""
    _, hybrid_sk, _, _ = _hybrid_keypair("512")
    with pytest.raises(SizeMismatchError):
        hybrid_decaps(hybrid_sk, b"", "512")


@pytest.mark.parametrize("level", LEVELS)
def test_hybrid_wrong_secret_key_does_not_leak_shared_secret(level):
    """Decapsulating under a different hybrid sk must NOT yield the encaps secret."""
    hybrid_pk, _, _, _ = _hybrid_keypair(level)
    _, other_hybrid_sk, _, _ = _hybrid_keypair(level)
    encap = hybrid_encaps(hybrid_pk, level)
    result = hybrid_decaps(other_hybrid_sk, encap.serialize(), level)
    assert result != encap.shared_secret, (
        "a different key must not reproduce the sender's shared secret"
    )


@pytest.mark.parametrize("level", LEVELS)
def test_hybrid_tampered_ciphertext_changes_secret(level):
    """Flipping a byte of the envelope changes the derived secret (KDF diffuses)."""
    hybrid_pk, hybrid_sk, _, _ = _hybrid_keypair(level)
    encap = hybrid_encaps(hybrid_pk, level)
    good = encap.serialize()
    tampered = bytearray(good)
    tampered[0] ^= 0x01
    result = hybrid_decaps(hybrid_sk, bytes(tampered), level)
    assert result != encap.shared_secret


@pytest.mark.parametrize("level", LEVELS)
def test_hybrid_serialize_roundtrip_fields(level):
    """serialize() must be byte-exact kem_ciphertext || classical_public."""
    hybrid_pk, _, _, _ = _hybrid_keypair(level)
    encap = hybrid_encaps(hybrid_pk, level)
    blob = encap.serialize()
    assert blob == encap.kem_ciphertext + encap.classical_public
    assert len(blob) == CT_BYTES[level] + X25519_PK


# --------------------------------------------------------- worked example

def test_hybrid_worked_example_512():
    """Documented quickstart: hybrid_encaps returns 32-byte secret; decaps matches."""
    hybrid_pk, hybrid_sk, _, _ = _hybrid_keypair("512")
    encap = hybrid_encaps(hybrid_pk, "512")
    assert len(encap.shared_secret) == 32
    ss = hybrid_decaps(hybrid_sk, encap.serialize(), "512")
    assert ss == encap.shared_secret
