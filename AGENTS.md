# Agent Guidelines: pqblocks-jose

Structured context for AI agents generating or modifying code that uses `pqblocks-jose`.

---

## Package Role & Mission

`pqblocks-jose` provides hybrid post-quantum cryptographic extensions for JOSE (Javascript Object Signing and Encryption):
- **Hybrid JWS**: ML-DSA-65 (FIPS 204) + Ed25519 dual composite digital signatures.
- **Hybrid JWE**: X25519 + ML-KEM-768 (FIPS 203) dual KEM with HKDF-SHA256 and AES-256-GCM.

---

## Primary Public API

All core classes and functions are exported from the top-level `pqblocks_jose` namespace:

```python
from pqblocks_jose import (
    Policy,
    generate_keypair,
    encode_jws,
    decode_jws,
    encrypt_jwe,
    decrypt_jwe,
    JWSResult,
    JWEResult,
    KeyPair,
)
from pqblocks_jose.exceptions import (
    JOSEError,
    InvalidTokenError,
    PolicyError,
    DecryptionError,
    VerificationError,
)
```

### Core Objects and Attributes

1. **`Policy`**:
   - `Policy(version=1, kem="X25519+MLKEM768", sig="MLDSA65+Ed25519", kdf="HKDF-SHA256", max_token_bytes=8192)`
   - Governs acceptable algorithms and maximum token payload sizes.
2. **`KeyPair`**:
   - Attributes: `.public_key` (bytes), `.private_key` (bytes), `.algorithm` (str), `.kid` (str or None).
3. **`JWSResult`**:
   - Attributes:
     - `.compact_serialization`: str (Base64url token `header.payload.signature`)
     - `.protected_header`: dict
     - `.payload`: str (JSON-encoded string) or dict
     - `.algorithm`: str
     - `.signature_verified`: bool
4. **`JWEResult`**:
   - Attributes:
     - `.compact_serialization`: str (Base64url token `header.encrypted_key.iv.ciphertext.tag`)
     - `.plaintext`: bytes (when decrypted)
     - `.encrypted_key`: bytes
     - `.enc`: str ("A256GCM")

---

## Critical Invariants

1. **Asymmetric Separation**:
   - `encode_jws`: Requires `private_key`.
   - `decode_jws`: Requires `public_key`.
   - `encrypt_jwe`: Requires `public_key`.
   - `decrypt_jwe`: Requires `private_key`.
2. **Token Size Floor**:
   - A hybrid JWS token is ~4.6 KB due to ML-DSA-65 signatures.
   - Never set `max_token_bytes` below `8192` when using hybrid signatures, or `PolicyError` will be raised.
3. **Dual Signature Requirement**:
   - Both ML-DSA-65 and Ed25519 must verify; the library will return `signature_verified=False` or raise `VerificationError` if either fails.

---

## Common AI Assistant Mistakes

| Mistake | Why it fails | Correct approach |
| :--- | :--- | :--- |
| Accessing `jws_result.claims` | `JWSResult` does not have a `.claims` property | Use `json.loads(jws_result.payload)` |
| Setting `max_token_bytes=4096` | Post-quantum tokens are ~4.6 KB | Keep default or set `max_token_bytes=8192` or higher |
| Supplying `seed` to `decode_jws` | Verification must supply the recipient's `public_key` | Pass `public_key=keypair.public_key` |
| Calling `decrypt_jwe` with `public_key` | Public keys cannot decrypt encapsulated ciphertext | Pass `private_key=keypair.private_key` |

---

## Minimal Canonical Example

```python
import json
from pqblocks_jose import Policy, generate_keypair, encode_jws, decode_jws

policy = Policy(max_token_bytes=8192)
keys = generate_keypair("ML-DSA-65-Ed25519")

# Encode
jws = encode_jws({"sub": "bot-user"}, policy, private_key=keys.private_key)

# Decode
res = decode_jws(jws.compact_serialization, policy, public_key=keys.public_key)
assert res.signature_verified is True
payload = json.loads(res.payload)
print(payload["sub"])
```
