# Security Notes & Threat Model for pqblocks-jose

This document outlines the security posture, operational limitations, threat model, and key management best practices for `pqblocks-jose`.

---

## 1. Cryptographic Boundaries & Implementation Safety

### Post-Quantum Primitives
- Post-quantum operations in `pqblocks-jose` delegate to `cryptography` (OpenSSL 3.x) for FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65).
- No mathematical primitives are implemented from scratch in pure Python for production operations.
- Hedged signing is enforced via OpenSSL to mitigate fault-injection and side-channel timing risks associated with deterministic signing.

### Hybrid Combiner Security
- **Dual Signatures**: The JWS construction embeds both ML-DSA-65 and Ed25519 signatures. Verification requires **both** signatures to validate. If an adversary breaks either algorithm, the authenticity of the token remains preserved by the unbroken algorithm.
- **Dual KEM**: The JWE construction encapsulates secrets across both X25519 and ML-KEM-768. The final AES-256-GCM key is derived via HKDF-SHA256 with domain-separated context information. Eavesdroppers must break **both** key encapsulations to decrypt the payload.

---

## 2. Operational Limitations & Known Characteristics

### Large Token Sizes & HTTP Headers
- Post-quantum signatures and public keys are significantly larger than classical counterparts:
  - ML-DSA-65 signatures alone require 3,309 bytes.
  - A compact hybrid JWS token measures ~4,641 bytes in base64url encoding.
- **Mitigation**: Standard web servers and reverse proxies (NGINX, Apache, Envoy) default to 4 KB or 8 KB header buffers. Systems accepting hybrid JWS headers must increase header buffer limits (e.g., `large_client_header_buffers 4 16k;` in NGINX) to avoid HTTP 431 ("Request Header Fields Too Large") errors.

### Wire Interoperability & Draft Specifications
- Standards for post-quantum JOSE tokens (`draft-ietf-jose-pq-composite-sigs` and related drafts) remain active in the IETF.
- `pqblocks-jose` uses an internal composite prefix (`0x0001`) and dual concatenated signatures. Tokens produced by this library are not intended for drop-in wire interchange with classical-only JWT libraries (e.g., PyJWT or Auth0 jwt libraries) unless configured with explicit hybrid support.

### CNSA 2.0 Scope
- The US National Security Agency (NSA) Commercial National Security Algorithm Suite 2.0 (CNSA 2.0) specifies ML-DSA-87 and ML-KEM-1024 for National Security Systems.
- `pqblocks-jose` currently standardizes on Security Category 3 (ML-DSA-65 and ML-KEM-768), which balances high post-quantum security with reasonable token size constraints for general enterprise architectures.

---

## 3. Key Handling and Storage Best Practices

1. **Seed Management**:
   - ML-DSA-65 private keys are represented as 32-byte seeds ($\xi$).
   - ML-KEM-768 private keys are represented as 64-byte seeds ($d \parallel z$).
   - Ensure seeds are generated using cryptographically secure random sources (`secrets.token_bytes` or `os.urandom`).
2. **Asymmetric Verification**:
   - Never use private keys for verification or public keys for decryption. `pqblocks-jose` raises explicit `KeyError` or type errors if asymmetric invariants are violated.
3. **Policy Pinning**:
   - Always instantiate and pass explicit `Policy` objects in production to prevent cipher downgrade attacks.

---

## 4. Formal Non-Claims

> [!IMPORTANT]
> `pqblocks-jose` is an open-source reference and enterprise library.
> - It is **not** certified under FIPS 140-3.
> - It has not undergone CMVP validation.
> - It is intended for post-quantum readiness, system prototyping, and hybrid transition architectures.
