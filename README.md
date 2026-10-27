# pqblocks-jose

[![PyPI version](https://img.shields.io/pypi/v/pqblocks-jose.svg)](https://pypi.org/project/pqblocks-jose/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python Versions](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)](https://pypi.org/project/pqblocks-jose/)

Post-quantum hybrid JOSE (Javascript Object Signing and Encryption) library providing hybrid JWS (JSON Web Signature) and hybrid JWE (JSON Web Encryption) tokens.

`pqblocks-jose` combines NIST post-quantum primitives (FIPS 203 ML-KEM-768 and FIPS 204 ML-DSA-65) with classical counterparts (X25519, Ed25519) to ensure security against both quantum and classical adversaries without compromising backwards security.

---

## Key Features

- **Hybrid JWS (Signatures)**: ML-DSA-65 + Ed25519 dual composite signature. Both signatures must verify; if either fails, the token is rejected.
- **Hybrid JWE (Encryption)**: Dual-KEM encapsulation using X25519 and ML-KEM-768 combined via HKDF-SHA256 (X-Wing combiner architecture) protecting AES-256-GCM authenticated payload encryption.
- **Misuse-Resistant API**:
  - Enforced `Policy` objects controlling accepted algorithms, token byte length limits, and KDF labels.
  - Strict asymmetric enforcement: Decryption requires a private key; public keys cannot decrypt.
  - Hardened against algorithm downgrade and parameter manipulation.
- **Standards & KAT Tested**:
  - Primitives verified against NIST ACVP (FIPS 203 / FIPS 204) and Google Project Wycheproof test vectors.
- **CLI Utility**: Bundled CLI for generating keypairs, encoding/decoding JWS, and encrypting/decrypting JWE.

---

## Installation

```bash
pip install pqblocks-jose
```

### System Dependencies

`pqblocks-jose` uses `cryptography` (OpenSSL-backed) for underlying cryptographic operations. If using the optional `liboqs` acceleration backend, ensure `liboqs.so` is available on your library search path:

```bash
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
```

---

## Quickstart

```python
from pqblocks_jose import Policy, generate_keypair, encode_jws, decode_jws, encrypt_jwe, decrypt_jwe

# 1. Define an enforceable policy
policy = Policy(
    version=1,
    kem="X25519+MLKEM768",           # Hybrid KEM for JWE
    sig="MLDSA65+Ed25519",           # Hybrid signature for JWS
    kdf="HKDF-SHA256",               # Mandatory KDF enforcement
    max_token_bytes=8192,            # Header-safe limit
    kdf_info="JOSE_PostQuantum_Traditional_Hybrid X25519MLKEM768",
    sig_alg_std="ML-DSA-65-Ed25519"
)

# 2. Generate hybrid keypairs
sign_keypair = generate_keypair("ML-DSA-65-Ed25519", seed=12345)
enc_keypair = generate_keypair("X25519+MLKEM768", seed=12345)

# 3. Sign & verify a JWS token
payload = {"sub": "alice@example.com", "iat": 1700000000, "aud": "api.internal"}
jws_result = encode_jws(payload, policy, private_key=sign_keypair.private_key)

# Verify with public key
verification = decode_jws(
    token=jws_result.compact_serialization,
    policy=policy,
    public_key=sign_keypair.public_key
)
print(f"JWS verified: {verification.signature_verified}")
print(f"JWS token size: {len(jws_result.compact_serialization)} bytes")

# 4. Encrypt & decrypt a JWE token
plaintext = b"session_key:random123nonce"
jwe_result = encrypt_jwe(plaintext, policy, public_key=enc_keypair.public_key)

# Decrypt with private key
decryption = decrypt_jwe(
    token=jwe_result.compact_serialization,
    policy=policy,
    private_key=enc_keypair.private_key
)
print(f"JWE decrypted matches: {decryption.plaintext == plaintext}")
```

---

## CLI Usage

The package installs the `pqblocks-jose` command-line tool:

```bash
# Print version and help
pqblocks-jose --version
pqblocks-jose --help

# Generate a hybrid keypair
pqblocks-jose generate keypair --algorithm "ML-DSA-65-Ed25519"

# Encode and decode JWS
pqblocks-jose encode jws --payload '{"sub":"admin","scope":"ops"}'
pqblocks-jose decode jws --token <TOKEN>

# Encrypt and decrypt JWE
pqblocks-jose encrypt jwe --plaintext "c2VjcmV0IGRhdGE="
pqblocks-jose decrypt jwe --token <TOKEN>
```

---

## Security Model & Non-Claims

> [!IMPORTANT]
> **Validation Status**: `pqblocks-jose` is an engineering implementation and research toolkit. It is **not** certified under FIPS 140-3, and has not undergone CMVP validation.
>
> **Wire Compatibility**:
> - JWS composite signatures use dual serialization (both ML-DSA-65 and Ed25519 concatenated under an internal prefix). They are not wire-compatible with single-algorithm classical JWT libraries.
> - JWE hybrid encryption uses an X-Wing style combiner with AES-256-GCM under custom parameter encodings.
>
> **Token Size Overhead**:
> Post-quantum public keys and signatures are substantially larger than classical RSA/ECDSA. A hybrid ML-DSA-65 + Ed25519 JWS is ~4.6 KB. Ensure reverse proxies and HTTP servers are configured with sufficient header buffers (e.g., 8 KB or 16 KB).

---

## License

This project is licensed under the Apache 2.0 License. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for details.
