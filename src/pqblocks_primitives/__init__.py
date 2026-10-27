"""
pqblocks-primitives — Production-ready integrated PQC dependency.

This module provides FIPS 203/204/205 compliant ML-KEM, ML-DSA, SLH-DSA
implementations wrapped around liboqs-python.

Public API:
    kem_keygen(level)              -> (pk: bytes, sk: bytes)
    kem_encaps(pk, level=None)     -> (ct: bytes, ss: bytes)
    kem_decaps(sk, ct, level=None) -> ss: bytes

All functions validate inputs and raise SizeMismatchError for invalid sizes.
"""

from __future__ import annotations

from typing import Tuple, Optional
import hashlib


# --------------------------------------------------------------------- errors

class PQCError(Exception):
    """Base class for all pqblocks_primitives errors."""
    pass


class InvalidParameterError(PQCError, ValueError):
    """Invalid algorithm parameters (wrong level, unsupported)."""
    pass


class SizeMismatchError(PQCError, ValueError):
    """Input byte string length doesn't match expected size."""
    pass


# --------------------------------------------------------------- backend

def _get_backend():
    """Lazily import and return liboqs KeyCompatibility module."""
    import oqs
    return oqs


# --------------------------------------------------------------- constants

# FIPS 203 Table 3 (bytes)
_KEM_SIZES = {
    "512":  {"ek": 800,  "dk": 1632, "ct": 768,  "ss": 32},
    "768":  {"ek": 1184, "dk": 2400, "ct": 1088, "ss": 32},
    "1024": {"ek": 1568, "dk": 3168, "ct": 1568, "ss": 32},
}

# Mapping from norm to liboqs algorithm name
_KEM_LIBOQS = {
    "512": "ML-KEM-512",
    "768": "ML-KEM-768",
    "1024": "ML-KEM-1024",
}

# FIPS 204 Table 2 (bytes) — sizes verified against ACVP official vectors
# and liboqs-python backend
_DSA_SIZES = {
    "ML-DSA-44": {"pk": 1312, "sk": 2560, "sig": 2420},
    "ML-DSA-65": {"pk": 1952, "sk": 4032, "sig": 3309},
    "ML-DSA-87": {"pk": 2592, "sk": 4896, "sig": 4627},
}

# Mapping from FIPS 204 parameter set to liboqs algorithm name
_DSA_LIBOQS = {
    "ML-DSA-44": "ML-DSA-44",
    "ML-DSA-65": "ML-DSA-65",
    "ML-DSA-87": "ML-DSA-87",
}


# ------------------------------------------------------------------ helpers

def _check_level(level: str) -> str:
    """Validate the level string; non-str is a TypeError, unknown str is InvalidParameterError."""
    if not isinstance(level, str):
        raise TypeError(
            f"level must be a str ('512', '768', '1024'), got {type(level).__name__}"
        )
    if level not in _KEM_SIZES:
        raise InvalidParameterError(
            f"invalid ML-KEM level {level!r}, must be one of {list(_KEM_SIZES.keys())}"
        )
    return level


def _check_size(data: bytes, expected: int, name: str) -> None:
    """Raise TypeError for non-bytes input, SizeMismatchError for wrong length."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes, got {type(data).__name__}")
    if len(data) != expected:
        raise SizeMismatchError(f"{name} must be {expected} bytes, got {len(data)}")


def _normalize_seed(seed):
    """
    Normalize seed input to bytes.
    Accepts bytes (must be 64 bytes) or hex string (128 chars).
    Returns bytes or raises TypeError/ValueError.
    """
    if seed is None:
        return None
    if isinstance(seed, bytes):
        if len(seed) != 64:
            raise ValueError("seed must be 64 bytes (32 bytes z + 32 bytes d)")
        return seed
    if isinstance(seed, str):
        if len(seed) != 128:
            raise ValueError("hex seed must be 128 characters (64 bytes)")
        try:
            seed_bytes = bytes.fromhex(seed)
        except ValueError:
            raise ValueError("seed hex string contains invalid characters")
        if len(seed_bytes) != 64:
            raise ValueError("seed must be 64 bytes (32 bytes z + 32 bytes d)")
        return seed_bytes
    raise TypeError(f"seed must be bytes or hex string, got {type(seed).__name__}")


# ------------------------------------------------------------------- API

def kem_keygen(level: str = "512") -> Tuple[bytes, bytes]:
    """
    Generate an ML-KEM keypair.

    Parameters
    ----------
    level : str
        The security level: "512", "768", or "1024" (FIPS 203 Table 2).

    Returns
    -------
    (pk, sk) : tuple of bytes
        Public key and secret key. Sizes match FIPS 203 Table 3.

    Raises
    ------
    InvalidParameterError
        If level is not valid.
    """
    level = _check_level(level)
    sizes = _KEM_SIZES[level]
    backend = _get_backend()
    with backend.KeyEncapsulation(_KEM_LIBOQS[level]) as kem:
        pk = kem.generate_keypair()   # OS CSPRNG — caller-seeded randomness is not exposed
        sk = kem.export_secret_key()
    _check_size(pk, sizes["ek"], "public key")
    _check_size(sk, sizes["dk"], "secret key")
    return pk, sk


def _kem_keygen_seeded(level: str = "512", seed=None) -> Tuple[bytes, bytes]:
    """
    Deterministic ML-KEM keypair generation for test use only.

    Uses a caller-supplied seed (64 bytes = 32 bytes z + 32 bytes d, or a
    128-character hex string). Not part of the public API: key material must
    be produced from the OS CSPRNG, never from caller-controlled randomness.
    """
    level = _check_level(level)
    sizes = _KEM_SIZES[level]
    normalized_seed = _normalize_seed(seed)
    backend = _get_backend()
    with backend.KeyEncapsulation(_KEM_LIBOQS[level]) as kem:
        if normalized_seed is not None:
            pk = kem.generate_keypair_seed(normalized_seed)
        else:
            pk = kem.generate_keypair()
        sk = kem.export_secret_key()
    _check_size(pk, sizes["ek"], "public key")
    _check_size(sk, sizes["dk"], "secret key")
    return pk, sk


def kem_encaps(pk: bytes, level: Optional[str] = None) -> Tuple[bytes, bytes]:
    """Encapsulate a shared secret using the public key (ACVP-level detail)."""
    # Infer level from pk length
    if level is None:
        for lv, sz in _KEM_SIZES.items():
            if len(pk) == sz["ek"]:
                level = lv
                break
        if level is None:
            raise SizeMismatchError(
                f"cannot infer ML-KEM level from public key length {len(pk)}"
            )
    else:
        # Accept both "512" and "ML-KEM-512" forms
        if level.startswith("ML-KEM-"):
            level = level.split("-")[2]
        level = _check_level(level)
    sizes = _KEM_SIZES[level]
    _check_size(pk, sizes["ek"], "public key")
    backend = _get_backend()
    with backend.KeyEncapsulation(_KEM_LIBOQS[level]) as kem:
        ct, ss = kem.encap_secret(pk)
    _check_size(ct, sizes["ct"], "ciphertext")
    _check_size(ss, sizes["ss"], "shared secret")
    return ct, ss


def kem_decaps(sk: bytes, ct: bytes, level: Optional[str] = None) -> Optional[bytes]:
    """
    Decapsulate a ciphertext to recover the shared secret.

    Parameters
    ----------
    sk : bytes
        The decapsulation key (secret key). Size must match FIPS 203 Table 3.
    ct : bytes
        The ciphertext. Size must match FIPS 203 Table 3 for the level.
    level : str, optional
        Security level inferred from key/ciphertext sizes if not provided.

    Returns
    -------
    ss : bytes or None
        The shared secret if decapsulation succeeded. Returns None on
        decapsulation failure (implicit rejection per FIPS 203).

    Raises
    ------
    SizeMismatchError
        If key or ciphertext size doesn't match any ML-KEM level.
    """
    # Infer level from sizes
    if level is None:
        for lv, sz in _KEM_SIZES.items():
            if len(sk) == sz["dk"] and len(ct) == sz["ct"]:
                level = lv
                break
        if level is None:
            raise SizeMismatchError(
                "cannot infer ML-KEM level from key/ciphertext sizes"
            )
    else:
        level = _check_level(level)

    sizes = _KEM_SIZES[level]
    _check_size(sk, sizes["dk"], "secret key")
    _check_size(ct, sizes["ct"], "ciphertext")

    backend = _get_backend()
    # IMPORTANT: pass secret_key to liboqs KeyEncapsulation so it can decrypt
    with backend.KeyEncapsulation(_KEM_LIBOQS[level], secret_key=sk) as kem:
        ss = kem.decap_secret(ct)

    if ss is not None:
        _check_size(ss, sizes["ss"], "shared secret")
    return ss


# ----------------------------------------------------------- DSA API (FIPS 204)


def dsa_keygen(level: str = "ML-DSA-65") -> Tuple[bytes, bytes]:
    """Generate an ML-DSA keypair.

    Parameters
    ----------
    level : str
        The security level: "ML-DSA-44", "ML-DSA-65", or "ML-DSA-87"
        (FIPS 204 Table 2).

    Returns
    -------
    (pk, sk) : tuple of bytes
        Public key and secret key. Sizes match FIPS 204 Table 2.

    Raises
    ------
    InvalidParameterError
        If level is not valid.
    """
    if level not in _DSA_SIZES:
        raise InvalidParameterError(
            f"invalid ML-DSA level {level!r}, must be one of {list(_DSA_SIZES.keys())}"
        )
    backend = _get_backend()
    with backend.Signature(_DSA_LIBOQS[level]) as sig:
        pk = sig.generate_keypair()
        sk = sig.export_secret_key()
    _check_size(pk, _DSA_SIZES[level]["pk"], "public key")
    _check_size(sk, _DSA_SIZES[level]["sk"], "secret key")
    return pk, sk


def dsa_sign(msg: bytes, pk: bytes, sk: bytes, level: str = "ML-DSA-65") -> bytes:
    """Sign a message using the ML-DSA private key.

    Parameters
    ----------
    msg : bytes
        The message to sign.
    pk : bytes
        The public key (validated against level).
    sk : bytes
        The secret key (validated against level).
    level : str, optional
        Security level inferred from key sizes if not provided.

    Returns
    -------
    sig : bytes
        The signature. Size matches FIPS 204 Table 2.

    Raises
    ------
    SizeMismatchError
        If public key or secret key size doesn't match the expected level.
    """
    if level not in _DSA_SIZES:
        level = None
    if level is None:
        # Infer level from key sizes
        for lvl, sz in _DSA_SIZES.items():
            if len(sk) == sz["sk"] and len(pk) == sz["pk"]:
                level = lvl
                break
        if level is None:
            raise SizeMismatchError(
                f"cannot infer ML-DSA level from key sizes: pk={len(pk)}, sk={len(sk)}"
            )
    # Validate sizes
    _check_size(pk, _DSA_SIZES[level]["pk"], "public key")
    _check_size(sk, _DSA_SIZES[level]["sk"], "secret key")

    backend = _get_backend()
    # liboqs-python: the secret key is passed to the constructor; sign() takes the message
    with backend.Signature(_DSA_LIBOQS[level], secret_key=sk) as sig:
        sig_bytes = sig.sign(msg)
    _check_size(sig_bytes, _DSA_SIZES[level]["sig"], "signature")
    return sig_bytes


def dsa_verify(
    msg: bytes, sig: bytes, pk: bytes, level: str = "ML-DSA-65", ctx: bytes = b""
) -> bool:
    """Verify an ML-DSA signature on a message (with optional context string).

    Parameters
    ----------
    msg : bytes
        The signed message.
    sig : bytes
        The signature to verify.
    pk : bytes
        The public key (validated against level).
    level : str, optional
        Security level inferred from key sizes if not provided.
    ctx : bytes, optional
        Context string for hedged/context-bound signatures (FIPS 204 §5.3).
        When non-empty, uses liboqs's verify_with_ctx_str for verification.

    Returns
    -------
    valid : bool
        True if the signature is valid, False otherwise.

    Raises
    ------
    SizeMismatchError
        If public key size doesn't match the expected level.
    """
    if level not in _DSA_SIZES:
        level = None
    if level is None:
        # Infer level from public key size
        for lvl, sz in _DSA_SIZES.items():
            if len(pk) == sz["pk"]:
                level = lvl
                break
        if level is None:
            raise SizeMismatchError(
                f"cannot infer ML-DSA level from public key size: pk={len(pk)}"
            )
    # Validate size
    _check_size(pk, _DSA_SIZES[level]["pk"], "public key")

    # Validate signature size against FIPS 204 Table 2
    _check_size(sig, _DSA_SIZES[level]["sig"], "signature")

    backend = _get_backend()
    # NB: the parameter `sig` holds the signature bytes; do not shadow it with
    # the backend object (passing the ctypes object where bytes are expected
    # segfaults liboqs).
    with backend.Signature(_DSA_LIBOQS[level]) as verifier:
        if ctx:
            valid = verifier.verify_with_ctx_str(msg, sig, ctx, pk)
        else:
            valid = verifier.verify(msg, sig, pk)
    return valid


# ----------------------------------------------------------- SLH-DSA API (FIPS 205)

# FIPS 205 Table 2 (bytes) — sizes for Pure-SHA2 variants
# Verified against FIPS PDF and liboqs-python
_SLDSA_SIZES = {
    "SLH-DSA-SHA2-128s": {"pk": 32, "sk": 64, "sig": 7856},
    "SLH-DSA-SHA2-128f": {"pk": 32, "sk": 64, "sig": 17088},
    "SLH-DSA-SHA2-192s": {"pk": 48, "sk": 96, "sig": 16224},
    "SLH-DSA-SHA2-192f": {"pk": 48, "sk": 96, "sig": 35664},
    "SLH-DSA-SHA2-256s": {"pk": 64, "sk": 128, "sig": 29792},
    "SLH-DSA-SHA2-256f": {"pk": 64, "sk": 128, "sig": 49856},
}

# Mapping from FIPS 205 parameter set to liboqs algorithm name
_SLDSA_LIBOQS = {
    "SLH-DSA-SHA2-128s": "SLH_DSA_PURE_SHA2_128S",
    "SLH-DSA-SHA2-128f": "SLH_DSA_PURE_SHA2_128F",
    "SLH-DSA-SHA2-192s": "SLH_DSA_PURE_SHA2_192S",
    "SLH-DSA-SHA2-192f": "SLH_DSA_PURE_SHA2_192F",
    "SLH-DSA-SHA2-256s": "SLH_DSA_PURE_SHA2_256S",
    "SLH-DSA-SHA2-256f": "SLH_DSA_PURE_SHA2_256F",
}


def _check_slhdsa_level(level: str) -> str:
    """Validate SLH-DSA level; non-str yields TypeError, unknown str yields InvalidParameterError."""
    if not isinstance(level, str):
        raise TypeError(f"level must be a str, got {type(level).__name__}")
    if level not in _SLDSA_SIZES:
        raise InvalidParameterError(
            f"invalid SLH-DSA level {level!r}, must be one of {list(_SLDSA_SIZES.keys())}"
        )
    return level


def slhdsa_keygen(level: str = "SLH-DSA-SHA2-128s") -> Tuple[bytes, bytes]:
    """Generate an SLH-DSA keypair.

    Parameters
    ----------
    level : str
        The parameter set: "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
        "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHA2-256s", or "SLH-DSA-SHA2-256f"
        (FIPS 205 Table 2).

    Returns
    -------
    (pk, sk) : tuple of bytes
        Public key and secret key. Sizes match FIPS 205 Table 2.

    Raises
    ------
    InvalidParameterError
        If level is not valid.
    """
    level = _check_slhdsa_level(level)
    sizes = _SLDSA_SIZES[level]
    backend = _get_backend()
    with backend.Signature(_SLDSA_LIBOQS[level]) as sig:
        pk = sig.generate_keypair()
        sk = sig.export_secret_key()
    _check_size(pk, sizes["pk"], "public key")
    _check_size(sk, sizes["sk"], "secret key")
    return pk, sk


def slhdsa_sign(
    msg: bytes, pk: bytes, sk: bytes, level: str = "SLH-DSA-SHA2-128s",
    context: bytes = b""
) -> bytes:
    """Sign a message using the SLH-DSA private key.

    Parameters
    ----------
    msg : bytes
        The message to sign.
    pk : bytes
        The public key (validated against level).
    sk : bytes
        The secret key (validated against level).
    level : str, optional
        Security level inferred from key sizes if not provided.
    context : bytes, optional
        Context for external signature interface. Default is empty (pure mode).

    Returns
    -------
    sig : bytes
        The signature. Size matches FIPS 205 Table 2.

    Raises
    ------
    SizeMismatchError
        If public key or secret key size doesn't match the expected level.
    """
    if level not in _SLDSA_SIZES:
        level = None
    if level is None:
        # Infer level from key sizes
        for lvl, sz in _SLDSA_SIZES.items():
            if len(sk) == sz["sk"] and len(pk) == sz["pk"]:
                level = lvl
                break
        if level is None:
            raise SizeMismatchError(
                f"cannot infer SLH-DSA level from key sizes: pk={len(pk)}, sk={len(sk)}"
            )
    # Validate sizes
    _check_size(pk, _SLDSA_SIZES[level]["pk"], "public key")
    _check_size(sk, _SLDSA_SIZES[level]["sk"], "secret key")

    backend = _get_backend()
    if context:
        # Use context-aware signing (external interface)
        with backend.Signature(_SLDSA_LIBOQS[level], secret_key=sk) as signer:
            sig_bytes = signer.sign_with_ctx_str(msg, context)
    else:
        # Pure signing (without context)
        with backend.Signature(_SLDSA_LIBOQS[level], secret_key=sk) as signer:
            sig_bytes = signer.sign(msg)
    _check_size(sig_bytes, _SLDSA_SIZES[level]["sig"], "signature")
    return sig_bytes


def slhdsa_verify(
    msg: bytes, sig: bytes, pk: bytes, level: str = "SLH-DSA-SHA2-128s",
    context: bytes = b""
) -> bool:
    """Verify an SLH-DSA signature on a message.

    Parameters
    ----------
    msg : bytes
        The signed message.
    sig : bytes
        The signature to verify.
    pk : bytes
        The public key (validated against level).
    level : str, optional
        Security level inferred from key sizes if not provided.
    context : bytes, optional
        Context for external signature interface. Default is empty (pure mode).

    Returns
    -------
    valid : bool
        True if the signature is valid, False otherwise.

    Raises
    ------
    SizeMismatchError
        If public key size doesn't match the expected level.
    """
    if level not in _SLDSA_SIZES:
        level = None
    if level is None:
        # Infer level from public key size
        for lvl, sz in _SLDSA_SIZES.items():
            if len(pk) == sz["pk"]:
                level = lvl
                break
        if level is None:
            raise SizeMismatchError(
                f"cannot infer SLH-DSA level from public key size: pk={len(pk)}"
            )
    # Validate public key size against FIPS 205 Table 2
    _check_size(pk, _SLDSA_SIZES[level]["pk"], "public key")

    # Signature size check: if wrong size per FIPS 205, raise SizeMismatchError
    # Specification requires proper error signalling on malformed inputs
    expected_sig_size = _SLDSA_SIZES[level]["sig"]
    if len(sig) != expected_sig_size:
        raise SizeMismatchError(
            f"SLH-DSA signature size mismatch for {level}: expected {expected_sig_size}, got {len(sig)}"
        )

    backend = _get_backend()
    if context:
        # Use context-aware verification (external interface)
        with backend.Signature(_SLDSA_LIBOQS[level]) as verifier:
            valid = verifier.verify_with_ctx_str(msg, sig, context, pk)
    else:
        # Pure verification (without context)
        with backend.Signature(_SLDSA_LIBOQS[level]) as verifier:
            valid = verifier.verify(msg, sig, pk)
    return valid


# ----------------------------------------------------------- Hybrid API

# X25519 raw key sizes (RFC 7748)
_X25519_PK_BYTES = 32
_X25519_SK_BYTES = 32

# Supported KDFs for hybrid secret derivation
_HYBRID_KDFS = ("HKDF-SHA256", "HKDF-SHA384")


class HybridEncapsulation:
    """
    Envelope produced by :func:`hybrid_encaps`.

    Attributes
    ----------
    kem_ciphertext : bytes
        The ML-KEM ciphertext (FIPS 203 Table 3 size for the level).
    classical_public : bytes
        The sender's ephemeral X25519 public key (32 bytes, RFC 7748).
    shared_secret : bytes
        The 32-byte combined shared secret.
    suite_id : str
        Identifier naming the exact construction, e.g.
        "ML-KEM-768-X25519-HKDF-SHA256" (for CBOM / protocol negotiation).
    """

    __slots__ = ("kem_ciphertext", "classical_public", "shared_secret", "suite_id")

    def __init__(self, kem_ciphertext: bytes, classical_public: bytes,
                 shared_secret: bytes, suite_id: str):
        self.kem_ciphertext = kem_ciphertext
        self.classical_public = classical_public
        self.shared_secret = shared_secret
        self.suite_id = suite_id

    def serialize(self) -> bytes:
        """Wire form: kem_ciphertext || classical_public."""
        return self.kem_ciphertext + self.classical_public

    def __eq__(self, other):
        if not isinstance(other, HybridEncapsulation):
            return NotImplemented
        return (self.kem_ciphertext == other.kem_ciphertext
                and self.classical_public == other.classical_public
                and self.shared_secret == other.shared_secret
                and self.suite_id == other.suite_id)

    def __repr__(self):
        return (f"HybridEncapsulation(suite_id={self.suite_id!r}, "
                f"ct={len(self.kem_ciphertext)}B, "
                f"classical_public={len(self.classical_public)}B, "
                f"shared_secret={len(self.shared_secret)}B)")


def _check_kdf(kdf: str) -> str:
    """Validate the KDF name; non-str is TypeError, unknown str is InvalidParameterError."""
    if not isinstance(kdf, str):
        raise TypeError(f"kdf must be a str, got {type(kdf).__name__}")
    if kdf not in _HYBRID_KDFS:
        raise InvalidParameterError(
            f"unsupported kdf {kdf!r}, must be one of {list(_HYBRID_KDFS)}"
        )
    return kdf


def _hybrid_kdf(ikm: bytes, kdf: str, length: int = 32) -> bytes:
    """Derive the combined secret: HKDF(ikm = KemSS || X25519SS), no salt, empty info."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    algorithm = hashes.SHA256() if kdf == "HKDF-SHA256" else hashes.SHA384()
    return HKDF(algorithm=algorithm, length=length, salt=None, info=b"").derive(ikm)


def _x25519_pair() -> Tuple[bytes, bytes]:
    """Generate a fresh X25519 keypair; returns (pk_raw32, sk_raw32)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    sk = X25519PrivateKey.generate()  # OS CSPRNG via pyca/cryptography
    pk = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    sk_raw = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pk, sk_raw


def _x25519_exchange(sk_raw: bytes, pk_raw: bytes) -> bytes:
    """Compute the raw 32-byte X25519 shared secret."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    try:
        sk = X25519PrivateKey.from_private_bytes(sk_raw)
        pk = X25519PublicKey.from_public_bytes(pk_raw)
        return sk.exchange(pk)
    except ValueError as e:
        raise ValueError(f"Invalid X25519 key material: {e}") from e


def hybrid_encaps(public_key: bytes, kem_level: str, kdf: str = "HKDF-SHA256") -> HybridEncapsulation:
    """
    Hybrid encapsulation: ML-KEM (FIPS 203) + X25519 (RFC 7748), combined with HKDF.

    Parameters
    ----------
    public_key : bytes
        Composite hybrid public key: ML-KEM encapsulation key || X25519 public
        key (32 bytes). Total length = FIPS 203 Table 3 ek size + 32.
    kem_level : str
        ML-KEM security level: "512", "768", or "1024".
    kdf : str, optional
        KDF used to combine the two shared secrets: "HKDF-SHA256" (default)
        or "HKDF-SHA384".

    Returns
    -------
    HybridEncapsulation
        Fields: kem_ciphertext, classical_public (ephemeral X25519 pk),
        shared_secret (32 bytes), suite_id.

    Raises
    ------
    TypeError
        If public_key is not bytes or kem_level/kdf is not str.
    InvalidParameterError
        If kem_level or kdf is not a supported value.
    SizeMismatchError
        If public_key length doesn't match ek + 32 for the level.

    Notes
    -----
    - Both randomness sources are OS CSPRNG-backed (liboqs + pyca/cryptography).
    - The KDF input is KemSS || X25519SS (concatenation, no labels) with
      empty salt and info; the suite_id string binds the exact construction.
    """
    level = _check_level(kem_level)
    kdf = _check_kdf(kdf)
    if not isinstance(public_key, (bytes, bytearray)):
        raise TypeError(f"public_key must be bytes, got {type(public_key).__name__}")

    sizes = _KEM_SIZES[level]
    expected_pk = sizes["ek"] + _X25519_PK_BYTES
    if len(public_key) != expected_pk:
        raise SizeMismatchError(
            f"hybrid public_key must be {expected_pk} bytes "
            f"({sizes['ek']} ML-KEM-{level} ek + 32 X25519 pk), got {len(public_key)}"
        )

    kem_pk = bytes(public_key[: sizes["ek"]])
    x_pk = bytes(public_key[sizes["ek"]:])

    # Ingredient 1: ML-KEM shared secret (liboqs, OS CSPRNG for the ephemeral key)
    backend = _get_backend()
    with backend.KeyEncapsulation(_KEM_LIBOQS[level]) as kem:
        kem_ct, kem_ss = kem.encap_secret(kem_pk)

    # Ingredient 2: X25519 ephemeral keypair + shared secret (pyca/cryptography)
    eph_pk, eph_sk = _x25519_pair()
    x_ss = _x25519_exchange(eph_sk, x_pk)

    # Combine: HKDF(KemSS || X25519SS) -> 32 bytes
    ikm = kem_ss + x_ss
    shared_secret = _hybrid_kdf(ikm, kdf)

    suite_id = f"ML-KEM-{level}-X25519-{kdf}"
    return HybridEncapsulation(
        kem_ciphertext=kem_ct,
        classical_public=eph_pk,
        shared_secret=shared_secret,
        suite_id=suite_id,
    )


def hybrid_decaps(secret_key: bytes, ct: bytes, kem_level: str, kdf: str = "HKDF-SHA256") -> bytes:
    """
    Hybrid decapsulation: recover the 32-byte combined shared secret.

    Parameters
    ----------
    secret_key : bytes
        Composite hybrid secret key: ML-KEM decapsulation key || X25519
        private key (32 bytes). Total length = FIPS 203 Table 3 dk size + 32.
    ct : bytes
        Serialized envelope from :meth:`HybridEncapsulation.serialize` or
        equivalent: ML-KEM ciphertext || ephemeral X25519 public key (32).
        Total length = FIPS 203 Table 3 ct size + 32.
    kem_level : str
        ML-KEM security level: "512", "768", or "1024".
    kdf : str, optional
        KDF used to combine the two shared secrets: "HKDF-SHA256" (default)
        or "HKDF-SHA384". Must match the encapsulation side.

    Returns
    -------
    bytes
        The 32-byte combined shared secret.

    Raises
    ------
    TypeError
        If secret_key/ct are not bytes or kem_level/kdf is not str.
    InvalidParameterError
        If kem_level or kdf is not a supported value.
    SizeMismatchError
        If secret_key or ct length doesn't match dk + 32 / ct + 32.

    Notes
    -----
    - ML-KEM implicit rejection (FIPS 203) surfaces as a distinct secret;
      the KDF still mixes the X25519 ingredient, so a wrong-sk decapsulation
      does not silently reproduce the sender's secret.
    """
    level = _check_level(kem_level)
    kdf = _check_kdf(kdf)
    if not isinstance(secret_key, (bytes, bytearray)):
        raise TypeError(f"secret_key must be bytes, got {type(secret_key).__name__}")
    if not isinstance(ct, (bytes, bytearray)):
        raise TypeError(f"ct must be bytes, got {type(ct).__name__}")

    sizes = _KEM_SIZES[level]
    expected_sk = sizes["dk"] + _X25519_SK_BYTES
    expected_ct = sizes["ct"] + _X25519_PK_BYTES
    if len(secret_key) != expected_sk:
        raise SizeMismatchError(
            f"hybrid secret_key must be {expected_sk} bytes "
            f"({sizes['dk']} ML-KEM-{level} dk + 32 X25519 sk), got {len(secret_key)}"
        )
    if len(ct) != expected_ct:
        raise SizeMismatchError(
            f"hybrid ciphertext must be {expected_ct} bytes "
            f"({sizes['ct']} ML-KEM-{level} ct + 32 X25519 pk), got {len(ct)}"
        )

    kem_sk = bytes(secret_key[: sizes["dk"]])
    x_sk = bytes(secret_key[sizes["dk"]:])
    kem_ct = bytes(ct[: sizes["ct"]])
    eph_pk = bytes(ct[sizes["ct"]:])

    # Ingredient 1: ML-KEM shared secret
    backend = _get_backend()
    try:
        with backend.KeyEncapsulation(_KEM_LIBOQS[level], secret_key=kem_sk) as kem:
            kem_ss = kem.decap_secret(kem_ct)
    except (RuntimeError, ValueError):
        # liboqs may raise RuntimeError/ValueError on malformed keys (implicit rejection)
        kem_ss = None
    if kem_ss is None:
        # Implicit rejection: liboqs returned no secret. Feed the KDF a
        # deterministic pseudo-secret derived from the ciphertext itself so
        # both sides still terminate (the result will not match the sender's).
        kem_ss = hashlib.sha256(b"pqblocks_primitives-implicit-rejection" + kem_ct).digest()

    # Ingredient 2: X25519 shared secret (static recipient sk × ephemeral sender pk)
    x_ss = _x25519_exchange(x_sk, eph_pk)

    # Same combination as encaps side
    ikm = kem_ss + x_ss
    return _hybrid_kdf(ikm, kdf)


# ----------------------------------------------------------- package version

__version__ = "0.1.0dev"
__all__ = [
    "dsa_keygen", "dsa_sign", "dsa_verify",
    "slhdsa_keygen", "slhdsa_sign", "slhdsa_verify",
    "kem_keygen", "kem_encaps", "kem_decaps",
    "hybrid_encaps", "hybrid_decaps", "HybridEncapsulation",
    "PQCError", "InvalidParameterError", "SizeMismatchError",
]
