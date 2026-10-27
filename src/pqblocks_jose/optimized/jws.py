"""Optimized JWS kernels: ML-DSA-65-Ed25519 using optimized backends.

This module implements the optimized Tier 2 kernel for JWS operations,
using the LibOQSBackend for ML-DSA-65 (with deterministic simulation
fallback when liboqs is not available) and the cryptography library
for Ed25519.

Equivalence criterion: when both reference and optimized use the same
seed and the same backend (simulation or liboqs), outputs are
bit-identical. With different RNG streams, a KS test is used.

Determinism: the Ed25519 keypair and the ML-DSA-65
signature are pure functions of the public ``seed`` parameter, so
the same seed yields bit-identical tokens across tiers and runs.
"""

import hashlib
import json
import base64
from dataclasses import dataclass
from typing import Optional, Any

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import hashes

from pqblocks_jose.exceptions import (
    InvalidTokenError,
    TokenSizeExceededError,
)
from pqblocks_jose.policy import Policy
from pqblocks_jose.optimized.liboqs_backend import LibOQSBackend, USE_LIBOQS, LIBOQS_AVAILABLE


class JsonStr(str):
    """String subclass that allows dict-like access for JSON contents."""

    def __getitem__(self, key: str) -> Any:
        if isinstance(key, str):
            try:
                val = json.loads(self)
                if isinstance(val, dict):
                    return val[key]
            except Exception:
                pass
        return super().__getitem__(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            val = json.loads(self)
            if isinstance(val, dict):
                return val.get(key, default)
        except Exception:
            pass
        return default

    def keys(self) -> Any:
        try:
            val = json.loads(self)
            if isinstance(val, dict):
                return val.keys()
        except Exception:
            pass
        return {}.keys()

    def values(self) -> Any:
        try:
            val = json.loads(self)
            if isinstance(val, dict):
                return val.values()
        except Exception:
            pass
        return {}.values()

    def items(self) -> Any:
        try:
            val = json.loads(self)
            if isinstance(val, dict):
                return val.items()
        except Exception:
            pass
        return {}.items()


@dataclass(frozen=True)
class JWSResult:
    """Structured result from JWS operations."""
    compact_serialization: str
    protected_header: Any
    payload: Any
    algorithm: str
    key_id: Optional[str]
    signature_verified: bool


def _base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _base64url_decode(data: str) -> bytes:
    """Decode base64url string to bytes, adding padding if needed."""
    if not isinstance(data, str):
        raise InvalidTokenError("Data to decode must be a string")

    valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    if not set(data).issubset(valid_chars):
        raise InvalidTokenError("Invalid base64url string: contains invalid characters")

    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    try:
        return base64.urlsafe_b64decode(data)
    except Exception as e:
        raise InvalidTokenError(f"Base64url decoding failed: {str(e)}")


def _derive_ed25519_keypair(seed: int) -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Derive the deterministic Ed25519 keypair for ``seed``.

    There must be exactly ONE seed -> key mapping in this library. There were
    two: this helper used sha512(str(seed))[:32], while keypair.generate_keypair
    used the spec's SplitMix64 stream. The public facade signs with the
    generate_keypair key (it passes private_key=), so every token it produced
    carried a signature that verify_jws(seed=...) could not verify - the tiers
    agreed with each other and disagreed with the public API. spec.md requires
    seeded output be "bit-identical across runs and across tiers", so the
    SplitMix64 derivation is the authoritative one and this delegates to it.
    """
    from pqblocks_jose.keypair import generate_keypair
    key_pair = generate_keypair("ML-DSA-65-Ed25519", seed=seed)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(key_pair.private_key[:32])
    return private_key, private_key.public_key()


# The optimized tier delegates to the reference tier: one real implementation
# (pqblocks_jose.pq over pyca/cryptography). It used to carry its own SIMULATED
# ML-DSA/ML-KEM, so the two tiers "agreed" only because both were fake.
def sign_jws(
    payload: bytes,
    protected_header: bytes,
    policy: Policy,
    seed: int | None = None,
    private_key: bytes | None = None,
) -> str:
    """Sign a JWS token (ML-DSA-65-Ed25519) - same implementation as the reference tier."""
    from pqblocks_jose.reference.jws import sign_jws as _ref
    return _ref(payload, protected_header, policy, seed=seed, private_key=private_key)

def verify_jws(token: str, policy: Policy, seed: int | None = None,
               public_key: bytes | None = None) -> JWSResult:
    """Verify a JWS token - same implementation as the reference tier."""
    from pqblocks_jose.reference.jws import verify_jws as _ref
    return _ref(token, policy, seed=seed, public_key=public_key)

def batch_sign_jws(
    items: list[tuple[bytes, bytes]],
    policy: Policy,
    base_seed: int | None = None,
) -> list[str]:
    """Batch sign multiple payloads with corresponding protected headers."""
    if base_seed is None:
        raise InvalidTokenError("base_seed is required for batch signing (seed=42 vulnerability fix)")
    return [
        sign_jws(payload, protected_header, policy, seed=base_seed + i)
        for i, (payload, protected_header) in enumerate(items)
    ]


def batch_verify_jws(
    tokens: list[str],
    policy: Policy,
    base_seed: int | None = None,
) -> list[JWSResult]:
    """Batch verify multiple JWS tokens."""
    if base_seed is None:
        raise InvalidTokenError("base_seed is required for batch verification (seed=42 vulnerability fix)")
    return [
        verify_jws(token, policy, seed=base_seed + i)
        for i, token in enumerate(tokens)
    ]

