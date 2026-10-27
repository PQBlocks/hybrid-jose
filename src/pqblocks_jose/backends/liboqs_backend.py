"""liboqs backend stub for pqblocks-jose.

This is a stub implementation of the PQBackend using liboqs.
Actual liboqs integration will be implemented in S6.
"""

from pqblocks_jose.backends.base import PQBackend
from typing import Tuple


class LibOQSBackend(PQBackend):
    """liboqs backend for post-quantum cryptographic operations.
    
    This is a stub implementation for S1. Actual liboqs integration
    will be implemented in feature S6.
    """

    def ml_dsa_keygen(self) -> Tuple[bytes, bytes]:
        """Generate ML-DSA-65 key pair using liboqs.
        
        Stub implementation - raises NotImplementedError.
        Actual implementation in S6.
        """
        raise NotImplementedError("liboqs ML-DSA-65 keygen not implemented yet")

    def ml_dsa_sign(self, sk: bytes, msg: bytes, ctx: bytes = b"") -> bytes:
        """Sign message using ML-DSA-65 private key via liboqs.
        
        Stub implementation - raises NotImplementedError.
        Actual implementation in S6.
        """
        raise NotImplementedError("liboqs ML-DSA-65 sign not implemented yet")

    def ml_dsa_verify(self, pk: bytes, msg: bytes, sig: bytes, ctx: bytes = b"") -> bool:
        """Verify signature using ML-DSA-65 public key via liboqs.
        
        Stub implementation - raises NotImplementedError.
        Actual implementation in S6.
        """
        raise NotImplementedError("liboqs ML-DSA-65 verify not implemented yet")

    def ml_kem_keygen(self) -> Tuple[bytes, bytes]:
        """Generate ML-KEM-768 key pair using liboqs.
        
        Stub implementation - raises NotImplementedError.
        Actual implementation in S6.
        """
        raise NotImplementedError("liboqs ML-KEM-768 keygen not implemented yet")

    def ml_kem_encaps(self, pk: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate secret using ML-KEM-768 public key via liboqs.
        
        Stub implementation - raises NotImplementedError.
        Actual implementation in S6.
        """
        raise NotImplementedError("liboqs ML-KEM-768 encaps not implemented yet")

    def ml_kem_decaps(self, sk: bytes, ct: bytes) -> bytes:
        """Decapsulate secret using ML-KEM-768 private key via liboqs.
        
        Stub implementation - raises NotImplementedError.
        Actual implementation in S6.
        """
        raise NotImplementedError("liboqs ML-KEM-768 decaps not implemented yet")

    def x25519_keygen(self) -> Tuple[bytes, bytes]:
        """Generate X25519 key pair.
        
        Stub implementation - raises NotImplementedError.
        Actual implementation will use liboqs X25519 in S6.
        """
        raise NotImplementedError("liboqs X25519 keygen not implemented yet")

    def x25519_dh(self, sk: bytes, pk: bytes) -> bytes:
        """Compute X25519 Diffie-Hellman shared secret.
        
        Stub implementation - raises NotImplementedError.
        Actual implementation will use liboqs X25519 in S6.
        """
        raise NotImplementedError("liboqs X25519 DH not implemented yet")

    def ed25519_keygen(self) -> Tuple[bytes, bytes]:
        """Generate Ed25519 key pair.
        
        Stub implementation - raises NotImplementedError.
        Actual implementation will use OpenSSL via cryptography in S7.
        """
        raise NotImplementedError("Ed25519 keygen not implemented yet")

    def ed25519_sign(self, sk: bytes, msg: bytes) -> bytes:
        """Sign message using Ed25519 private key.
        
        Stub implementation - raises NotImplementedError.
        Actual implementation will use OpenSSL via cryptography in S7.
        """
        raise NotImplementedError("Ed25519 sign not implemented yet")

    def ed25519_verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        """Verify signature using Ed25519 public key.
        
        Stub implementation - raises NotImplementedError.
        Actual implementation will use OpenSSL via cryptography in S7.
        """
        raise NotImplementedError("Ed25519 verify not implemented yet")