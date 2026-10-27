"""PQ Backends for pqblocks-jose.

This module provides backend implementations for post-quantum and classical
cryptographic operations needed for hybrid JWS/JWE tokens.

Backends:
    - PQBackend: Abstract base class defining the interface
    - LibOQSBackend: Backend using liboqs for PQ primitives (stub in S1)
    - OpenSSLBackend: Backend using OpenSSL for classical primitives (stub in S1)
"""

from pqblocks_jose.backends.base import PQBackend
from pqblocks_jose.backends.liboqs_backend import LibOQSBackend
from pqblocks_jose.backends.openssl_backend import OpenSSLBackend

__all__ = [
    "PQBackend",
    "LibOQSBackend", 
    "OpenSSLBackend",
]

# Backend selection logic
# - LibOQSBackend will be used for ML-DSA/ML-KEM operations (S6 implementation)
# - OpenSSLBackend will be used for X25519/Ed25519 operations (S7 implementation)
# - Hybrid operations will use both backends together

# Default backend selection based on operation type
def get_backend(operation: str) -> PQBackend:
    """Return the appropriate backend for an operation.
    
    Args:
        operation: One of 'ml_dsa', 'ml_kem', 'x25519', 'ed25519'
        
    Returns:
        Backend instance for the given operation
        
    Note:
        This is S1's backend selection logic. Actual backend
        implementations will be in S6 (liboqs) and S7 (OpenSSL).
    """
    if operation in ('ml_dsa', 'ml_kem'):
        return LibOQSBackend()
    elif operation in ('x25519', 'ed25519'):
        return OpenSSLBackend()
    else:
        raise ValueError(f"Unknown operation: {operation}")