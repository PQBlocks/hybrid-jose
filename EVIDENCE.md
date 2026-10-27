# Cryptographic Evidence & Standards Traceability

This document details the standards, specifications, and external test corpora used to verify cryptographic implementations in `pqblocks-jose`.

---

## Standards and Specifications

| Specification | Organization | Area of Implementation | Status in Library |
| :--- | :--- | :--- | :--- |
| **FIPS 203** | NIST | ML-KEM-768 key encapsulation | Implemented via `cryptography` / OpenSSL 3.x; verified via ACVP KAT |
| **FIPS 204** | NIST | ML-DSA-65 digital signatures | Implemented via `cryptography` / OpenSSL 3.x; verified via ACVP KAT |
| **RFC 7515** | IETF | JSON Web Signature (JWS) | Base serialization, protected headers, compact encoding |
| **RFC 7516** | IETF | JSON Web Encryption (JWE) | Base envelope format, compact serialization |
| **draft-ietf-jose-pq-composite-sigs** | IETF | Dual composite signature model | Inspiration for dual ML-DSA-65 + Ed25519; wire format uses custom internal prefix |
| **draft-connolly-cfrg-xwing-kem** | IETF / CFRG | Hybrid KEM combiner | Combiner architecture (X25519 + ML-KEM-768 with HKDF-SHA256 label) |
| **RFC 8032** | IETF | Edwards-Curve Digital Signature (Ed25519) | Classical component of dual signature |
| **RFC 7748** | IETF | Elliptic Curves for Security (X25519) | Classical component of dual KEM |
| **RFC 5869** | IETF | HMAC-based Extract-and-Expand Key Derivation (HKDF) | Shared secret derivation in hybrid KEM |
| **NIST SP 800-38D** | NIST | Galois/Counter Mode (AES-GCM) | Content encryption (A256GCM) |

---

## Test Vectors and Evidence Mapping

| Claim | Test File | Vector Corpus / Specification Source | Result |
| :--- | :--- | :--- | :--- |
| **ML-DSA-65 SigVer** | `tests/test_kat_acvp.py`, `tests/test_official_vectors.py` | NIST ACVP `ML-DSA-sigVer-FIPS204` internal projection | PASS |
| **ML-DSA-65 SigGen** | `tests/test_official_vectors.py` | NIST ACVP `ML-DSA-sigGen-FIPS204` deterministic test groups | PASS |
| **ML-KEM-768 KeyGen** | `tests/test_official_vectors.py` | NIST ACVP `ML-KEM-keyGen-FIPS203` internal projection | PASS |
| **ML-DSA-65 Robustness** | `tests/test_kat_wycheproof.py` | Project Wycheproof `mldsa_65_verify_test.json` | PASS |
| **Ed25519 Verification** | `tests/test_kat_wycheproof.py` | Project Wycheproof `ed25519_test.json` | PASS |
| **Dual Signature Verification** | `tests/test_ref_jws.py` | Synthetic tests requiring both classical and PQC signature valid | PASS |
| **Hybrid JWE AEAD Integrity** | `tests/test_ref_jwe.py` | Modified ciphertext / tag injection tests | PASS (DecryptionError) |
| **Policy Invariance** | `tests/test_policy.py` | Algorithm mismatch, downgrade attempts, size enforcement | PASS |
| **Key Store & JWK/JWKS** | `tests/test_keystore.py` | Key serialization, private key isolation, parsing | PASS |

---

## Cryptographic Design Notes

1. **No Primitive Invention**:
   - `pqblocks-jose` does not implement post-quantum mathematical kernels from scratch. All low-level operations delegate to `cryptography` (OpenSSL 3.x) or optional `liboqs`.
2. **Dual Signature Security**:
   - Verification fails if either the classical (Ed25519) or post-quantum (ML-DSA-65) signature fails. An attacker breaking ML-DSA cannot forge tokens unless Ed25519 is also compromised, and vice versa.
3. **Dual KEM Security**:
   - The hybrid shared secret is derived by hashing the concatenation of X25519 and ML-KEM-768 shared secrets via HKDF-SHA256 under domain-separated context information. A break of either primitive does not expose the payload encryption key.
