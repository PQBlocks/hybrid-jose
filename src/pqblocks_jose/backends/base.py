"""PQ Backend Abstract Base Class for pqblocks-jose.

This module defines the abstract backend interface that all PQ backends
must implement. It follows the Template Method pattern and defines the
required primitives for hybrid JWS/JWE operations.
"""

from abc import ABC, abstractmethod
from typing import Tuple, Optional


class PQBackend(ABC):
    """Abstract base class for post-quantum cryptographic backends.
    
    This class defines the interface that all PQ backends must implement
    to provide the cryptographic primitives needed for hybrid JWS/JWE
    operations in pqblocks-jose.
    """

    @abstractmethod
    def ml_dsa_keygen(self) -> Tuple[bytes, bytes]:
        """Generate ML-DSA-65 key pair.
        
        Returns:
            Tuple of (public_key, private_key) as bytes.
            
        Raises:
            NotImplementedError: If not implemented by subclass.
        """
        raise NotImplementedError("ml_dsa_keygen not implemented")

    @abstractmethod
    def ml_dsa_sign(self, sk: bytes, msg: bytes, ctx: bytes = b"") -> bytes:
        """Sign message using ML-DSA-65 private key.
        
        Args:
            sk: ML-DSA-65 private key
            msg: Message to sign
            ctx: Context (must be empty per RFC 9964)
            
        Returns:
            Signature as bytes
            
        Raises:
            NotImplementedError: If not implemented by subclass.
        """
        raise NotImplementedError("ml_dsa_sign not implemented")

    @abstractmethod
    def ml_dsa_verify(self, pk: bytes, msg: bytes, sig: bytes, ctx: bytes = b"") -> bool:
        """Verify signature using ML-DSA-65 public key.
        
        Args:
            pk: ML-DSA-65 public key
            msg: Message that was signed
            sig: Signature to verify
            ctx: Context (must be empty per RFC 9964)
            
        Returns:
            True if signature is valid, False otherwise
            
        Raises:
            NotImplementedError: If not implemented by subclass.
        """
        raise NotImplementedError("ml_dsa_verify not implemented")

    @abstractmethod
    def ml_kem_keygen(self) -> Tuple[bytes, bytes]:
        """Generate ML-KEM-768 key pair.
        
        Returns:
            Tuple of (public_key, private_key) as bytes.
            
        Raises:
            NotImplementedError: If not implemented by subclass.
        """
        raise NotImplementedError("ml_kem_keygen not implemented")

    @abstractmethod
    def ml_kem_encaps(self, pk: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate secret using ML-KEM-768 public key.
        
        Args:
            pk: ML-KEM-768 public key
            
        Returns:
            Tuple of (ciphertext, shared_secret) as bytes.
            
        Raises:
            NotImplementedError: If not implemented by subclass.
        """
        raise NotImplementedError("ml_kem_encaps not implemented")

    @abstractmethod
    def ml_kem_decaps(self, sk: bytes, ct: bytes) -> bytes:
        """Decapsulate secret using ML-KEM-768 private key.
        
        Args:
            sk: ML-KEM-768 private key
            ct: Ciphertext to decapsulate
            
        Returns:
            Shared secret as bytes
            
        Raises:
            NotImplementedError: If not implemented by subclass.
        """
        raise NotImplementedError("ml_kem_decaps not implemented")

    @abstractmethod
    def x25519_keygen(self) -> Tuple[bytes, bytes]:
        """Generate X25519 key pair.
        
        Returns:
            Tuple of (public_key, private_key) as bytes.
            
        Raises:
            NotImplementedError: If not implemented by subclass.
        """
        raise NotImplementedError("x25519_keygen not implemented")

    @abstractmethod
    def x25519_dh(self, sk: bytes, pk: bytes) -> bytes:
        """Compute X25519 Diffie-Hellman shared secret.
        
        Args:
            sk: X25519 private key
            pk: X25519 public key
            
        Returns:
            Shared secret as bytes
            
        Raises:
            NotImplementedError: If not implemented by subclass.
        """
        raise NotImplementedError("x25519_dh not implemented")

    @abstractmethod
    def ed25519_keygen(self) -> Tuple[bytes, bytes]:
        """Generate Ed25519 key pair.
        
        Returns:
            Tuple of (public_key, private_key) as bytes.
            
        Raises:
            NotImplementedError: If not implemented by subclass.
        """
        raise NotImplementedError("ed25519_keygen not implemented")

    @abstractmethod
    def ed25519_sign(self, sk: bytes, msg: bytes) -> bytes:
        """Sign message using Ed25519 private key.
        
        Args:
            sk: Ed25519 private key
            msg: Message to sign
            
        Returns:
            Signature as bytes
            
        Raises:
            NotImplementedError: If not implemented by subclass.
        """
        raise NotImplementedError("ed25519_sign not implemented")

    @abstractmethod
    def ed25519_verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        """Verify signature using Ed25519 public key.
        
        Args:
            pk: Ed25519 public key
            msg: Message that was signed
            sig: Signature to verify
            
        Returns:
            True if signature is valid, False otherwise
            
        Raises:
            NotImplementedError: If not implemented by subclass.
        """
        raise NotImplementedError("ed25519_verify not implemented")