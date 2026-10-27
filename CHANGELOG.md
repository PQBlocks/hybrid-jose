# Changelog

All notable changes to `pqblocks-jose` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-26

### Added
- **Hybrid JWS Signatures**: Dual composite digital signature combining NIST FIPS 204 ML-DSA-65 and RFC 8032 Ed25519 with dual verification enforcement.
- **Hybrid JWE Encryption**: Dual KEM authenticated encryption combining NIST FIPS 203 ML-KEM-768 and RFC 7748 X25519 using HKDF-SHA256 key derivation and AES-256-GCM.
- **Security Policy Engine**: Configurable `Policy` objects enforcing permitted algorithms, token length ceilings, and protocol identifiers to prevent downgrade attacks.
- **Key Store**: In-memory and extensible key stores supporting JWK and JWKS representation for post-quantum hybrid keys.
- **Command-Line Interface**: `pqblocks-jose` CLI executable for key generation, token encoding, token decoding, encryption, and decryption.
- **Cryptographic Test Suite**: Comprehensive test suite with 406 passing tests, including NIST ACVP FIPS 203/204 test vector verification and Google Project Wycheproof edge-case testing.
- **Documentation**: Complete documentation set including performance benchmarks, testing guides, cryptographic evidence mapping, security architecture notes, agent instructions, and deployment recipes.
