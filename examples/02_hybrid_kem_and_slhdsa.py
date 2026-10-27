"""Example 2: End-to-End Post-Quantum & Hybrid Cryptography Pipeline.

Demonstrates:
1. Hybrid Key Encapsulation (ML-KEM-768 + X25519 with HKDF-SHA256).
2. Stateless Hash-Based Digital Signatures (SLH-DSA-SHA2-128s, FIPS 205).
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from pqblocks_primitives import (
    kem_keygen,
    hybrid_encaps,
    hybrid_decaps,
    slhdsa_keygen,
    slhdsa_sign,
    slhdsa_verify,
)

def main():
    print("1. Testing Hybrid Key Encapsulation (ML-KEM-768 + X25519)...")
    # Generate ML-KEM-768 component
    kem_pk, kem_sk = kem_keygen("768")

    # Generate classical X25519 component
    x_sk = x25519.X25519PrivateKey.generate()
    x_pk = x_sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    x_sk_bytes = x_sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Compose hybrid keypairs
    hybrid_pk = kem_pk + x_pk
    hybrid_sk = kem_sk + x_sk_bytes
    print(f"   Hybrid PK length: {len(hybrid_pk)} bytes (ML-KEM-768 1184 + X25519 32)")
    print(f"   Hybrid SK length: {len(hybrid_sk)} bytes (ML-KEM-768 2400 + X25519 32)")

    # Encapsulate
    encap = hybrid_encaps(hybrid_pk, "768", kdf="HKDF-SHA256")
    wire_ct = encap.serialize()
    print(f"   Ciphertext length: {len(wire_ct)} bytes (ML-KEM-768 1088 + X25519 32)")
    print(f"   Shared Secret length: {len(encap.shared_secret)} bytes")

    # Decapsulate
    ss_recovered = hybrid_decaps(hybrid_sk, wire_ct, "768", kdf="HKDF-SHA256")
    assert encap.shared_secret == ss_recovered, "Hybrid shared secret mismatch!"
    print("   [PASS] Hybrid shared secret agreed successfully.")

    print("\n2. Testing SLH-DSA Digital Signatures (SLH-DSA-SHA2-128s, FIPS 205)...")
    pk_sig, sk_sig = slhdsa_keygen("SLH-DSA-SHA2-128s")
    print(f"   SLH-DSA PK length: {len(pk_sig)} bytes")
    print(f"   SLH-DSA SK length: {len(sk_sig)} bytes")

    message = b"Quantum-resistant attestation payload v1"
    context = b"audit-ctx"
    signature = slhdsa_sign(message, pk_sig, sk_sig, "SLH-DSA-SHA2-128s", context=context)
    print(f"   Signature length: {len(signature)} bytes")

    # Verify signature
    valid = slhdsa_verify(message, signature, pk_sig, "SLH-DSA-SHA2-128s", context=context)
    assert valid, "SLH-DSA verification failed!"
    print("   [PASS] SLH-DSA signature verified successfully.")

    # Tamper test
    tampered_msg = b"Tampered payload"
    invalid = slhdsa_verify(tampered_msg, signature, pk_sig, "SLH-DSA-SHA2-128s", context=context)
    assert not invalid, "Tampered signature should not verify!"
    print("   [PASS] Tampered message correctly rejected.")

    print("\nAll post-quantum primitive operations completed successfully.")

if __name__ == "__main__":
    main()
