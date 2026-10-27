# Testing Guide for pqblocks-jose

This guide documents test suites, external Known Answer Test (KAT) vector validation, coverage metrics, and execution procedures.

---

## Test Execution

Run the complete test suite using `pytest`:

```bash
pytest -v
```

To run with statement coverage reporting:

```bash
pytest --cov=pqblocks_jose --cov-report=term-missing
```

---

## Test Suite Summary

- **Total Collected**: 408 tests
- **Passing**: 406 passed
- **Skipped**: 2 skipped (optional environment/acceleration fallbacks)
- **Execution Time**: ~5.3 seconds
- **Statement Coverage**: 81% across 1,435 statements

### Coverage by Component

| Module | Statements | Missing | Coverage | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `pqblocks_jose/__init__.py` | 49 | 3 | 94% | Top-level exports and convenience helpers |
| `backends/base.py` | 36 | 0 | 100% | Abstract cryptographic backend interfaces |
| `backends/liboqs_backend.py` | 25 | 0 | 100% | Optional liboqs backend adapter |
| `backends/openssl_backend.py` | 25 | 0 | 100% | OpenSSL / pyca backend adapter |
| `exceptions.py` | 19 | 0 | 100% | Error hierarchy |
| `keypair.py` | 68 | 14 | 79% | Keypair representation & serialization |
| `keystore.py` | 183 | 10 | 95% | JWK / JWKS key store management |
| `policy.py` | 45 | 0 | 100% | Security policy constraints and validation |
| `pq.py` | 42 | 2 | 95% | Direct FIPS 203/204 bindings via OpenSSL |
| `reference/jwe.py` | 186 | 26 | 86% | Reference hybrid JWE implementation |
| `reference/jws.py` | 238 | 37 | 84% | Reference hybrid JWS implementation |
| `optimized/jwe.py` | 139 | 44 | 68% | Fast-path hybrid JWE kernel |
| `optimized/jws.py` | 88 | 12 | 86% | Fast-path hybrid JWS kernel |
| `optimized/openssl_backend.py` | 73 | 6 | 92% | Direct CFFI OpenSSL engine bindings |
| **Total** | **1,435** | **270** | **81%** | |

---

## Known Answer Tests (KAT)

`pqblocks-jose` validates cryptographic correctness against vendored official test corpora located in `tests/vectors/`:

1. **NIST ACVP (Automated Cryptographic Validation Protocol)**:
   - `ML-DSA-sigVer-FIPS204`: Tests signature verification against official NIST ACVP test groups across various context lengths and pure pre-hash configurations.
   - `ML-DSA-sigGen-FIPS204`: Tests ML-DSA-65 signature generation against deterministic NIST reference outputs.
   - `ML-KEM-keyGen-FIPS203`: Tests ML-KEM-768 key generation from fixed seed vectors `d` and `z`.

2. **Project Wycheproof**:
   - `mldsa_65_verify_test.json`: Checks boundary conditions, malformed signatures, modified messages, and invalid encodings.
   - `ed25519_test.json`: Wycheproof validation of Ed25519 signing and verification components.

---

## Property-Based Testing

Extensive property tests using `hypothesis` test:
- Arbitrary payload lengths and binary content.
- Rejection of tampered ciphertext, authentication tags, and initialization vectors.
- Preservation of policy invariants across token serialization roundtrips.
- Error handling on malformed JSON and corrupted base64url inputs.

---

## CLI Integration Tests

The CLI test suite in `tests/test_cli.py` verifies subprocess execution of the `pqblocks-jose` executable for:
- Help (`--help`) and version (`--version`) commands.
- Keypair generation across supported algorithms.
- Encoding, decoding, encryption, and decryption of JWS and JWE tokens.
- Exit code and error reporting for invalid commands or malformed inputs.
