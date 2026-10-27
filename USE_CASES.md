# Deployment Use Cases for pqblocks-jose

This document provides copy-pasteable recipes for integrating `pqblocks-jose` into production environments.

---

## 1. Microservice API Authentication (Hybrid JWS Bearer Tokens)

Issue quantum-safe hybrid bearer tokens from an authentication service and verify them across downstream microservices.

```python
import time
from pqblocks_jose import Policy, generate_keypair, encode_jws, decode_jws

# Shared authentication policy
AUTH_POLICY = Policy(
    version=1,
    sig="MLDSA65+Ed25519",
    max_token_bytes=8192,
    sig_alg_std="ML-DSA-65-Ed25519"
)

# Issuer generates signing keys (store securely in KMS / HSM)
issuer_keys = generate_keypair("ML-DSA-65-Ed25519")

def issue_token(user_id: str, roles: list[str]) -> str:
    claims = {
        "sub": user_id,
        "roles": roles,
        "iss": "auth.service.internal",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600
    }
    result = encode_jws(claims, AUTH_POLICY, private_key=issuer_keys.private_key)
    return result.compact_serialization

def verify_token(raw_token: str) -> dict:
    verification = decode_jws(
        token=raw_token,
        policy=AUTH_POLICY,
        public_key=issuer_keys.public_key
    )
    if not verification.signature_verified:
        raise ValueError("Invalid signature")
    import json
    return json.loads(verification.payload)

# Example usage
token = issue_token("user_1024", ["billing:view", "reports:read"])
claims = verify_token(token)
print(f"Authenticated user: {claims['sub']}, roles: {claims['roles']}")
```

---

## 2. Confidential Service-to-Service Payloads (Hybrid JWE)

Encrypt confidential database connection strings or credentials transmitted across untrusted networks or message queues.

```python
from pqblocks_jose import Policy, generate_keypair, encrypt_jwe, decrypt_jwe

TRANSPORT_POLICY = Policy(
    version=1,
    kem="X25519+MLKEM768",
    kdf="HKDF-SHA256",
    max_token_bytes=16384
)

# Destination service publishes its hybrid public key
db_service_keys = generate_keypair("X25519+MLKEM768")

def send_encrypted_secret(secret_bytes: bytes) -> str:
    jwe = encrypt_jwe(
        plaintext=secret_bytes,
        policy=TRANSPORT_POLICY,
        public_key=db_service_keys.public_key
    )
    return jwe.compact_serialization

def receive_encrypted_secret(encrypted_token: str) -> bytes:
    decryption = decrypt_jwe(
        token=encrypted_token,
        policy=TRANSPORT_POLICY,
        private_key=db_service_keys.private_key
    )
    return decryption.plaintext

# Example usage
secret_conn_str = b"postgres://app:supersecret@10.0.0.5:5432/finance_db"
ciphertext = send_encrypted_secret(secret_conn_str)
recovered = receive_encrypted_secret(ciphertext)
assert recovered == secret_conn_str
print("Successfully decrypted confidential payload.")
```

---

## 3. Strict Algorithmic Policy Enforcement

Enforce zero-trust security policies to reject token downgrade attacks or unauthorized algorithm combinations.

```python
import pytest
from pqblocks_jose import Policy, generate_keypair, encode_jws, decode_jws
from pqblocks_jose.exceptions import PolicyError

# Strict corporate policy enforcing only ML-DSA-65 dual signatures
strict_policy = Policy(
    version=2,
    sig="MLDSA65+Ed25519",
    max_token_bytes=8192
)

# Incompatible policy allowing legacy algorithms
legacy_policy = Policy(
    version=1,
    sig="Ed25519",  # Classical only
    max_token_bytes=8192
)

keys = generate_keypair("ML-DSA-65-Ed25519")
token = encode_jws({"sub": "admin"}, strict_policy, private_key=keys.private_key)

# Downstream receiver rejecting token if validated under mismatched policy
try:
    decode_jws(token.compact_serialization, legacy_policy, public_key=keys.public_key)
except PolicyError as e:
    print(f"Policy enforcement successfully prevented mismatch: {e}")
```

---

## 4. Key Management and JWKS Key Stores

Store and retrieve hybrid post-quantum keys with metadata and key IDs.

```python
from pqblocks_jose.keystore import MemoryKeyStore
from pqblocks_jose.keypair import KeyPair

keystore = MemoryKeyStore()

# Register hybrid signing key with unique kid
key = KeyPair.generate("ML-DSA-65-Ed25519", kid="auth-key-2026-q4")
keystore.add_key(key)

# Lookup key by identifier
retrieved = keystore.get_key("auth-key-2026-q4")
print(f"Retrieved key algorithm: {retrieved.algorithm}, kid: {retrieved.kid}")
```
