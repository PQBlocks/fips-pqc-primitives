# Use Cases: pqblocks-primitives

## 1. Hybrid Transport Encryption

Establish quantum-safe symmetric keys combining classical Elliptic Curve Diffie-Hellman (X25519) and lattice-based KEM (ML-KEM-768):

```python
from pqblocks_primitives import kem_keygen, hybrid_encaps, hybrid_decaps
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

# Generate keys
kem_pk, kem_sk = kem_keygen("768")
x_sk = x25519.X25519PrivateKey.generate()
x_pk = x_sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
x_sk_bytes = x_sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())

hybrid_pk = kem_pk + x_pk
hybrid_sk = kem_sk + x_sk_bytes

# Sender encapsulates session key
encap = hybrid_encaps(hybrid_pk, "768")
send_to_peer(encap.serialize())

# Receiver decapsulates session key
shared_key = hybrid_decaps(hybrid_sk, received_wire_ct, "768")
```

## 2. Post-Quantum Identity & Code Signing

Sign firmware images, software packages, or transaction attestations using ML-DSA or SLH-DSA:

```python
from pqblocks_primitives import dsa_keygen, dsa_sign, dsa_verify

pk, sk = dsa_keygen("ML-DSA-65")
artifact = open("firmware.bin", "rb").read()

signature = dsa_sign(artifact, pk, sk, "ML-DSA-65")
```

## 3. High-Security Hash-Based Long-Term Signatures

For environments requiring signature security based solely on the collision resistance of standard hash functions (without lattice assumptions), utilize SLH-DSA:

```python
from pqblocks_primitives import slhdsa_keygen, slhdsa_sign, slhdsa_verify

pk, sk = slhdsa_keygen("SLH-DSA-SHA2-128s")
sig = slhdsa_sign(b"Root CA Certificate", pk, sk, "SLH-DSA-SHA2-128s", context=b"ca-issuance")
```
