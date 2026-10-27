"""Reference implementation for JWS: ML-DSA-65-Ed25519.

This is the pure-Python reference implementation that serves as the correctness
oracle. It uses cryptography for Ed25519 (classical) and stubbed PQBackend
for ML-DSA-65 (PQ primitives not yet available in release pipeline env).

Deterministic key generation via SHA-512 seed derivation ensures reproducible
signing across runs and tiers.
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
from pqblocks_jose import pq
from pqblocks_jose.policy import Policy


class JsonStr(str):
    """String subclass that allows dict-like access for JSON contents."""

    def __getitem__(self, key: str) -> Any:
        if isinstance(key, str):
            val = json.loads(self)
            if isinstance(val, dict):
                return val[key]
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
        val = json.loads(self)
        return val.keys() if isinstance(val, dict) else [].keys()

    def values(self) -> Any:
        val = json.loads(self)
        return val.values() if isinstance(val, dict) else [].values()

    def items(self) -> Any:
        val = json.loads(self)
        return val.items() if isinstance(val, dict) else [].items()


@dataclass(frozen=True)
class JWSResult:
    """Structured result from JWS operations."""
    compact_serialization: str
    protected_header: Any
    payload: Any
    algorithm: str
    key_id: Optional[str]
    signature_verified: bool


# Deterministic key seed for reproducible reference implementation
_DEFAULT_SEED = b"pqblocks-jose-reference-seed-v1"


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


def _base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _base64url_decode(data: str) -> bytes:
    """Decode base64url string to bytes, adding padding if needed."""
    if not isinstance(data, str):
        raise InvalidTokenError("Data to decode must be a string")
    
    # Check for valid base64url characters only
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


def _parse_jwt(compact_jws: str) -> tuple[bytes, bytes, str]:
    """Parse compact JWT into protected header (bytes), payload (bytes), and signature_b64 (str)."""
    parts = compact_jws.split('.')
    if len(parts) != 3:
        raise InvalidTokenError("Invalid JWT structure: must have 3 parts")

    protected_header_b64 = parts[0]
    payload_b64 = parts[1]
    signature_b64 = parts[2]

    protected_header = _base64url_decode(protected_header_b64)
    payload = _base64url_decode(payload_b64)

    return protected_header, payload, signature_b64


# ML-DSA-65 is real (pyca/cryptography via pqblocks_jose.pq). Until 2026-10-07
# this module "signed" with b"simulated_ml_dsa_65_signature_" + H(msg) and
# "verified" by recomputing it - no key involved, so anyone could forge.


def sign_jws(
    payload: bytes,
    protected_header: bytes,
    policy: Policy,
    seed: int | None = None,
    private_key: bytes | None = None,
    public_key: bytes | None = None,
) -> str:
    """Sign a JWS token using ML-DSA-65-Ed25519.

    Args:
        payload: The JWT payload bytes
        protected_header: The JWS protected header bytes
        policy: The policy object containing constraints
        seed: Deterministic seed for key generation. Required if
            private_key is not provided and public_key is not provided. Omitting seed without
            private_key or public_key raises InvalidTokenError to prevent seed=42 forgery vulnerability.
        private_key: Optional pre-generated private key bytes. If provided,
            seed is ignored. Enables proper asymmetric API.
        public_key: Optional pre-generated public key bytes for signing.
            When provided, seed is ignored.

    Returns:
        str: Compact serialization of the JWS token

    Raises:
        TokenSizeExceededError: If the token exceeds policy.max_token_bytes
        InvalidTokenError: If input is malformed or neither seed nor private_key provided
    """
    if seed is None and private_key is None and public_key is None:
        raise InvalidTokenError("Either 'seed', 'private_key', or 'public_key' must be provided (seed=42 vulnerability fix)")
    if not isinstance(payload, bytes) or not isinstance(protected_header, bytes):
        raise InvalidTokenError("Payload and protected header must be bytes")

    try:
        protected_header_dict = json.loads(protected_header.decode('utf-8'))
        if not isinstance(protected_header_dict, dict):
            raise InvalidTokenError("Protected header must be a JSON object")
    except Exception as e:
        raise InvalidTokenError(f"Malformed protected header: {str(e)}")
    # never sign a header that does not name the algorithm actually used
    if protected_header_dict.get("alg") != "ML-DSA-65-Ed25519":
        raise InvalidTokenError("Protected header alg must be ML-DSA-65-Ed25519")

    try:
        payload_dict = json.loads(payload.decode('utf-8'))
        if not isinstance(payload_dict, dict):
            raise InvalidTokenError("Payload must be a JSON object")
    except Exception as e:
        raise InvalidTokenError(f"Malformed payload: {str(e)}")

    # Signing needs the PRIVATE key: ed25519_sk(32B) || ml_dsa_65_seed(32B),
    # given directly or derived from the seed. A public key cannot sign.
    if private_key is None:
        if seed is None:
            raise InvalidTokenError("signing requires private_key or seed; a public key cannot sign")
        from pqblocks_jose.keypair import generate_keypair as _gk
        private_key = _gk("ML-DSA-65-Ed25519", seed=seed).private_key
    if len(private_key) != 64:
        raise InvalidTokenError(f"Invalid private key length: {len(private_key)} != 64")
    ed25519_sk = ed25519.Ed25519PrivateKey.from_private_bytes(private_key[:32])
    ml_dsa_seed = private_key[32:64]

    # Build signing input per draft-ietf-jose-pq-composite-sigs-03 §5.1
    protected_header_b64 = _base64url_encode(protected_header)
    payload_b64 = _base64url_encode(payload)
    signing_input = protected_header_b64 + "." + payload_b64

    # ML-DSA-65 over the SHA-512 pre-hash of the signing input (draft §5.1)
    msg_pq = hashlib.sha512(signing_input.encode('utf-8')).digest()
    sig_pq = pq.mldsa65_sign(ml_dsa_seed, msg_pq)

    # Ed25519 sign with real cryptography
    sig_cl_bytes = ed25519_sk.sign(signing_input.encode('utf-8'))
    sig_cl = sig_cl_bytes[:64].ljust(64, b"0")[:64]

    # Composite signature per draft Table 5
    prefix = b"\x00\x01"
    sig_comp = prefix + sig_pq + sig_cl

    signature_b64 = _base64url_encode(sig_comp)
    compact_serialization = f"{protected_header_b64}.{payload_b64}.{signature_b64}"

    # Check token size against policy
    token_size = len(compact_serialization.encode('utf-8'))
    if token_size > policy.max_token_bytes:
        raise TokenSizeExceededError(token_size, policy.max_token_bytes)

    return compact_serialization


def verify_jws(
    token: str,
    policy: Policy,
    seed: int | None = None,
    public_key: bytes | None = None,
) -> JWSResult:
    """Verify a JWS token using ML-DSA-65-Ed25519.

    Args:
        token: The compact JWT string
        policy: The policy object containing constraints
        seed: Deterministic seed for key generation. Required if
            public_key is not provided. Raises InvalidTokenError if None and no public_key.
        public_key: Optional pre-generated public key bytes for verification.
            When provided, seed is ignored.

    Returns:
        JWSResult: Structured result containing the decoded components and verification status

    Raises:
        InvalidTokenError: If token is malformed, header is invalid, or signature verification fails
        TokenSizeExceededError: If the token exceeds policy.max_token_bytes
    """
    if seed is None and public_key is None:
        raise InvalidTokenError("Either 'seed' or 'public_key' must be provided (seed=42 vulnerability fix)")
    if seed is not None and public_key is not None:
        from pqblocks_jose.keypair import generate_keypair as _gk
        if _gk("ML-DSA-65-Ed25519", seed=seed).public_key != public_key:
            raise InvalidTokenError("public_key does not match seed-derived key")

    try:
        protected_header, payload, signature_b64 = _parse_jwt(token)
    except Exception as e:
        raise InvalidTokenError(f"Malformed JWT: {str(e)}")

    # Check token size
    token_size = len(token.encode('utf-8'))
    if token_size > policy.max_token_bytes:
        raise TokenSizeExceededError(token_size, policy.max_token_bytes)

    try:
        protected_header_dict = json.loads(protected_header.decode('utf-8'))
        if not isinstance(protected_header_dict, dict):
            raise InvalidTokenError("Protected header must be a JSON object")
        algorithm = protected_header_dict.get("alg", "unknown")
        if algorithm != "ML-DSA-65-Ed25519":
            raise InvalidTokenError(f"Unsupported algorithm: {algorithm}")
        key_id = protected_header_dict.get("kid")
    except InvalidTokenError:
        raise
    except Exception as e:
        raise InvalidTokenError(f"Failed to parse protected header: {str(e)}")

    try:
        payload_dict = json.loads(payload.decode('utf-8'))
        if not isinstance(payload_dict, dict):
            raise InvalidTokenError("Payload must be a JSON object")
    except Exception as e:
        raise InvalidTokenError(f"Failed to decode payload: {str(e)}")

    try:
        sig_bytes = _base64url_decode(signature_b64)
    except Exception as e:
        raise InvalidTokenError(f"Failed to decode signature: {str(e)}")

    if len(sig_bytes) != 3375:
        raise InvalidTokenError(f"Invalid signature length: {len(sig_bytes)} != 3375")

    if not sig_bytes.startswith(b"\x00\x01"):
        raise InvalidTokenError("Invalid composite signature prefix: must start with 0x00 0x01")

    # Extract signature components
    prefix = sig_bytes[0:2]
    sig_pq = sig_bytes[2:3311]  # 3309 bytes
    sig_cl = sig_bytes[3311:3375]  # 64 bytes

    if prefix != b"\x00\x01":
        raise InvalidTokenError("Invalid composite signature prefix: must be 0x00 0x01")

    # Reconstruct signing input
    protected_header_b64 = _base64url_encode(protected_header)
    payload_b64 = _base64url_encode(payload)
    signing_input = protected_header_b64 + "." + payload_b64

    # Verify ML-DSA-65 component
    msg_pq = hashlib.sha512(signing_input.encode('utf-8')).digest()
    # One key, both halves: the explicit public key, or the seed's
    if public_key is None:
        from pqblocks_jose.keypair import generate_keypair as _gk
        public_key = _gk("ML-DSA-65-Ed25519", seed=seed).public_key
    if len(public_key) != 1984:
        raise InvalidTokenError(f"Invalid public key length: {len(public_key)} != 1984")
    ok_pq = pq.mldsa65_verify(public_key[32:1984], msg_pq, sig_pq)
    ed25519_pk = ed25519.Ed25519PublicKey.from_public_bytes(public_key[:32])
    ok_cl = False
    try:
        ed25519_pk.verify(sig_cl, signing_input.encode('utf-8'))
        ok_cl = True
    except Exception:
        ok_cl = False

    signature_verified = ok_pq and ok_cl

    if not signature_verified:
        raise InvalidTokenError("Signature verification failed")

    return JWSResult(
        compact_serialization=token,
        protected_header=JsonStr(protected_header.decode('utf-8')),
        payload=JsonStr(payload.decode('utf-8')),
        algorithm=algorithm,
        key_id=key_id,
        signature_verified=signature_verified
    )


def verify_jws_with_key(token: str, policy: Policy, public_key: bytes) -> JWSResult:
    """Verify a JWS token using a provided public key (asymmetric API).

    This is the proper verification API for production use. The public_key
    should be the public key from a KeyPair generated via generate_keypair().

    Args:
        token: The compact JWT string
        policy: The policy object containing constraints
        public_key: The public key bytes from a KeyPair (classical||PQ concatenated)

    Returns:
        JWSResult: Structured result containing the decoded components and verification status
    """
    if not isinstance(token, str):
        raise InvalidTokenError("Token must be a string")

    try:
        protected_header, payload, signature_b64 = _parse_jwt(token)
    except Exception as e:
        raise InvalidTokenError(f"Malformed JWT: {str(e)}")

    # Check token size
    token_size = len(token.encode('utf-8'))
    if token_size > policy.max_token_bytes:
        raise TokenSizeExceededError(token_size, policy.max_token_bytes)

    try:
        protected_header_dict = json.loads(protected_header.decode('utf-8'))
        if not isinstance(protected_header_dict, dict):
            raise InvalidTokenError("Protected header must be a JSON object")
        algorithm = protected_header_dict.get("alg", "unknown")
        if algorithm != "ML-DSA-65-Ed25519":
            raise InvalidTokenError(f"Unsupported algorithm: {algorithm}")
        key_id = protected_header_dict.get("kid")
    except InvalidTokenError:
        raise
    except Exception as e:
        raise InvalidTokenError(f"Failed to parse protected header: {str(e)}")

    try:
        payload_dict = json.loads(payload.decode('utf-8'))
        if not isinstance(payload_dict, dict):
            raise InvalidTokenError("Payload must be a JSON object")
    except Exception as e:
        raise InvalidTokenError(f"Failed to decode payload: {str(e)}")

    try:
        sig_bytes = _base64url_decode(signature_b64)
    except Exception as e:
        raise InvalidTokenError(f"Failed to decode signature: {str(e)}")

    if len(sig_bytes) != 3375:
        raise InvalidTokenError(f"Invalid signature length: {len(sig_bytes)} != 3375")

    if not sig_bytes.startswith(b"\x00\x01"):
        raise InvalidTokenError("Invalid composite signature prefix: must start with 0x00 0x01")

    # Extract signature components
    prefix = sig_bytes[0:2]
    sig_pq = sig_bytes[2:3311]  # 3309 bytes
    sig_cl = sig_bytes[3311:3375]  # 64 bytes

    if prefix != b"\x00\x01":
        raise InvalidTokenError("Invalid composite signature prefix: must be 0x00 0x01")

    # Reconstruct signing input
    protected_header_b64 = _base64url_encode(protected_header)
    payload_b64 = _base64url_encode(payload)
    signing_input = protected_header_b64 + "." + payload_b64

    # Verify ML-DSA-65 component using provided public key
    # public_key format: ed25519_pk(32B) || ml_dsa_pk(1952B)
    if len(public_key) != 1984:  # 32 + 1952, exactly
        raise InvalidTokenError(f"Invalid public key length: {len(public_key)} bytes")
    
    ed25519_pk_bytes = public_key[:32]
    ml_dsa_pk_bytes = public_key[32:1984]

    # Verify Ed25519 component with actual public key
    from cryptography.hazmat.primitives.asymmetric import ed25519
    ed25519_pk = ed25519.Ed25519PublicKey.from_public_bytes(ed25519_pk_bytes)
    ok_cl = False
    try:
        ed25519_pk.verify(sig_cl, signing_input.encode('utf-8'))
        ok_cl = True
    except Exception:
        ok_cl = False

    # Verify ML-DSA-65 with the provided public key
    msg_pq = hashlib.sha512(signing_input.encode('utf-8')).digest()
    ok_pq = pq.mldsa65_verify(ml_dsa_pk_bytes, msg_pq, sig_pq)

    signature_verified = ok_pq and ok_cl

    if not signature_verified:
        raise InvalidTokenError("Signature verification failed")

    return JWSResult(
        compact_serialization=token,
        protected_header=JsonStr(protected_header.decode('utf-8')),
        payload=JsonStr(payload.decode('utf-8')),
        algorithm=algorithm,
        key_id=key_id,
        signature_verified=signature_verified
    )
