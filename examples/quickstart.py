from pqblocks_primitives import kem_keygen, kem_encaps, kem_decaps, dsa_keygen, dsa_sign, dsa_verify

# ML-KEM key exchange
pk, sk = kem_keygen("512")
ct, ss1 = kem_encaps(pk, "512")
ss2 = kem_decaps(sk, ct, "512")
assert ss1 == ss2  # True — verified in this session

# ML-DSA signature
pk2, sk2 = dsa_keygen("ML-DSA-65")
sig = dsa_sign(b"message", pk2, sk2, "ML-DSA-65")
assert dsa_verify(b"message", sig, pk2, "ML-DSA-65")  # True
