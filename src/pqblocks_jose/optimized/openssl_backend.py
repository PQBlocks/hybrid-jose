"""OpenSSL backend for pqblocks-jose.

This module implements the PQBackend interface using the `cryptography` library
for classical primitives (X25519, Ed25519) and delegates ML-DSA/ML-KEM
operations to LibOQSBackend (since cryptography v50.0.1 does not yet expose
FIPS 203/204 primitives via the EVP API; OpenSSL 3.6+ would add native support).

Classical primitives use `cryptography.hazmat.primitives.asymmetric` directly.
PQ primitives are proxied to the optimized liboqs backend for consistency.
"""

from __future__ import annotations

from typing import Tuple
from pqblocks_jose.backends.base import PQBackend

try:
    from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
    from cryptography.hazmat.primitives import serialization
except ImportError:
    # This should not happen in the release pipeline env, but handle gracefully
    x25519 = None  # type: ignore
    ed25519 = None  # type: ignore
    serialization = None  # type: ignore

# Import the liboqs backend for PQ delegation
_LIBOQS_BACKEND = None
try:
    from pqblocks_jose.optimized.liboqs_backend import LibOQSBackend
    _LIBOQS_BACKEND = LibOQSBackend()
except ImportError:
    pass


class OpenSSLBackend(PQBackend):
    """OpenSSL backend for classical cryptographic operations via `cryptography`.

    This backend provides:
    - X25519 key exchange via `cryptography.hazmat.primitives.asymmetric.x25519`
    - Ed25519 signing/verification via `cryptography.hazmat.primitives.asymmetric.ed25519`
    - ML-DSA-65 and ML-KEM-768 delegated to LibOQSBackend (FIPS 203/204)
      because `cryptography` v50.0.1 lacks these primitives.

    When `cryptography` 50.0.1 gains ML-DSA/ML-KEM support (OpenSSL 3.6+),
    this backend can be extended to use native EVP_PKEY APIs instead of
    delegating to liboqs.
    """

    # ------------------------------------------------------------------
    # ML-DSA / ML-KEM: delegated to LibOQSBackend
    # ------------------------------------------------------------------

    def ml_dsa_keygen(self) -> Tuple[bytes, bytes]:
        """Generate ML-DSA-65 key pair via delegated LibOQSBackend."""
        if _LIBOQS_BACKEND is None:
            raise RuntimeError("LibOQSBackend not available for ML-DSA keygen")
        return _LIBOQS_BACKEND.ml_dsa_keygen()

    def ml_dsa_sign(self, sk: bytes, msg: bytes, ctx: bytes = b"") -> bytes:
        """Sign message using ML-DSA-65 private key via delegated LibOQSBackend."""
        if _LIBOQS_BACKEND is None:
            raise RuntimeError("LibOQSBackend not available for ML-DSA sign")
        return _LIBOQS_BACKEND.ml_dsa_sign(sk, msg, ctx)

    def ml_dsa_verify(self, pk: bytes, msg: bytes, sig: bytes, ctx: bytes = b"") -> bool:
        """Verify signature using ML-DSA-65 public key via delegated LibOQSBackend."""
        if _LIBOQS_BACKEND is None:
            raise RuntimeError("LibOQSBackend not available for ML-DSA verify")
        return _LIBOQS_BACKEND.ml_dsa_verify(pk, msg, sig, ctx)

    def ml_kem_keygen(self) -> Tuple[bytes, bytes]:
        """Generate ML-KEM-768 key pair via delegated LibOQSBackend."""
        if _LIBOQS_BACKEND is None:
            raise RuntimeError("LibOQSBackend not available for ML-KEM keygen")
        return _LIBOQS_BACKEND.ml_kem_keygen()

    def ml_kem_encaps(self, pk: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate secret using ML-KEM-768 public key via delegated LibOQSBackend."""
        if _LIBOQS_BACKEND is None:
            raise RuntimeError("LibOQSBackend not available for ML-KEM encaps")
        return _LIBOQS_BACKEND.ml_kem_encaps(pk)

    def ml_kem_decaps(self, sk: bytes, ct: bytes) -> bytes:
        """Decapsulate secret using ML-KEM-768 private key via delegated LibOQSBackend."""
        if _LIBOQS_BACKEND is None:
            raise RuntimeError("LibOQSBackend not available for ML-KEM decaps")
        return _LIBOQS_BACKEND.ml_kem_decaps(sk, ct)

    # ------------------------------------------------------------------
    # X25519 (RFC 7748) via cryptography
    # ------------------------------------------------------------------

    def x25519_keygen(self) -> Tuple[bytes, bytes]:
        """Generate X25519 key pair using cryptography library.

        Returns:
            Tuple of (public_key, private_key) as 32-byte bytes each.
        """
        if x25519 is None or serialization is None:
            raise RuntimeError("cryptography library not available for X25519")
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return (
            public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
            private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )

    def x25519_dh(self, sk: bytes, pk: bytes) -> bytes:
        """Compute X25519 Diffie-Hellman shared secret.

        Args:
            sk: 32-byte X25519 private key.
            pk: 32-byte X25519 public key.

        Returns:
            32-byte shared secret.
        """
        if x25519 is None:
            raise RuntimeError("cryptography library not available for X25519 DH")
        private_key = x25519.X25519PrivateKey.from_private_bytes(sk)
        public_key = x25519.X25519PublicKey.from_public_bytes(pk)
        return bytes(private_key.exchange(public_key))

    # ------------------------------------------------------------------
    # Ed25519 (RFC 8032) via cryptography
    # ------------------------------------------------------------------

    def ed25519_keygen(self) -> Tuple[bytes, bytes]:
        """Generate Ed25519 key pair using cryptography library.

        Returns:
            Tuple of (public_key, private_key_seed) as 32-byte bytes each.
        """
        if ed25519 is None or serialization is None:
            raise RuntimeError("cryptography library not available for Ed25519")
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return (
            public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
            private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )

    def ed25519_sign(self, sk: bytes, msg: bytes) -> bytes:
        """Sign message using Ed25519 private key.

        Args:
            sk: 32-byte Ed25519 private key seed.
            msg: Message to sign.

        Returns:
            64-byte Ed25519 signature.
        """
        if ed25519 is None:
            raise RuntimeError("cryptography library not available for Ed25519 sign")
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(sk)
        return bytes(private_key.sign(msg))

    def ed25519_verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        """Verify Ed25519 signature.

        Args:
            pk: 32-byte Ed25519 public key.
            msg: Original message.
            sig: 64-byte signature to verify.

        Returns:
            True if signature is valid, False otherwise.
        """
        if ed25519 is None:
            raise RuntimeError("cryptography library not available for Ed25519 verify")
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pk)
        try:
            public_key.verify(sig, msg)
            return True
        except Exception:
            return False