"""Optimized backend implementations for pqblocks-jose.

This package contains the optimized cryptographic primitives using
actual liboqs bindings via CFFI where available, with deterministic
simulation fallback for development/testing when liboqs is not installed.
"""

from pqblocks_jose.optimized.liboqs_backend import LibOQSBackend
from pqblocks_jose.optimized.jws import (
    sign_jws,
    verify_jws,
    batch_sign_jws,
    batch_verify_jws,
)
from pqblocks_jose.optimized.jwe import (
    encrypt_jwe,
    decrypt_jwe,
    batch_encrypt_jwe,
    batch_decrypt_jwe,
)

__all__ = [
    "LibOQSBackend",
    "sign_jws",
    "verify_jws",
    "batch_sign_jws",
    "batch_verify_jws",
    "encrypt_jwe",
    "decrypt_jwe",
    "batch_encrypt_jwe",
    "batch_decrypt_jwe",
]