"""pqblocks-jose: Hybrid JWT/JOSE with ML-DSA-65 + ML-KEM-768.

This package provides a misuse-resistant JWT/JOSE SDK layer exposing
hybrid algorithm identifiers (ML-DSA-65 + Ed25519 for signing,
X25519 + ML-KEM-768 for encryption) with mandatory KDF enforcement,
versioned policy objects, and self-describing envelopes.

Note: This is NOT quantum crypto - it wraps liboqs/OpenSSL for the
actual PQC primitives. ",
honestly benchmarked."

Version: 0.1.0-dev (S5 feature)
"""

__version__ = "0.1.0-dev"

from pqblocks_jose.backends import PQBackend, LibOQSBackend, OpenSSLBackend
# InvalidTokenError was imported function-locally inside encode_jws() and
# encrypt_jwe() only, so decode_jws() - which raises it twice, once for a missing
# public_key and once when a supplied seed does not match the supplied key -
# referenced an undefined name. Both of those are SECURITY guards: the second is
# the forgery check itself. A caller doing `except InvalidTokenError` therefore
# did not catch a forgery attempt; it got an uncaught NameError instead, which
# turns a clean rejection into a crash. Import it once, at module level.
from pqblocks_jose.exceptions import (
    InvalidTokenError,
    TokenSizeExceededError,
    DecryptionError,
    ReplayDetectedError,
    PolicyMismatchError,
    KeyFormatError,
)
from pqblocks_jose.reference.jws import (
    sign_jws,
    verify_jws,
    verify_jws_with_key,
    JWSResult,
    JsonStr,
    _base64url_encode,
)
from pqblocks_jose.reference.jwe import (
    encrypt_jwe as _ref_encrypt_jwe,
    decrypt_jwe as _ref_decrypt_jwe,
    JWEResult,
)
from pqblocks_jose.optimized.jwe import (
    encrypt_jwe as _opt_encrypt_jwe,
    decrypt_jwe as _opt_decrypt_jwe,
)
from pqblocks_jose.keypair import KeyPair, generate_keypair
from pqblocks_jose.policy import Policy

__all__ = [
    "__version__",
    "PQBackend",
    "LibOQSBackend",
    "OpenSSLBackend",
    "JWSResult",
    "JWEResult",
    "KeyPair",
    "JsonStr",
    "Policy",
    "encode_jws",
    "decode_jws",
    "encrypt_jwe",
    "decrypt_jwe",
    "generate_keypair",
    "sign_jws",
    "verify_jws",
    "verify_jws_with_key",
]


def encode_jws(
    payload: dict,
    policy: Policy,
    *,
    seed: int | None = None,
    private_key: bytes | None = None,
    kid: str | None = None,
) -> JWSResult:
    """Encode a JWT payload into a hybrid JWS token (ML-DSA-65-Ed25519).

    This is the recommended high-level API. It handles key generation
    (deterministic via seed parameter) and token encoding together.

    Args:
        payload: Dict of claims to serialize as JSON.
        policy: Versioned policy object enforcing constraints.
        seed: Deterministic seed for key generation. Required if
            private_key is not provided. Omitting seed without private_key
            raises InvalidTokenError to prevent seed=42 forgery vulnerability.
        private_key: Optional pre-generated private key bytes. If provided,
            seed is ignored. Enables proper asymmetric API where verification
            requires public_key, not seed re-derivation.
        kid: Optional key identifier; included in the protected header.

    Returns:
        JWSResult with structured fields. The payload and protected_header
        fields are plain dicts (not JsonStr) for convenience.

    Raises:
        InvalidTokenError: if payload or header is malformed, or if neither
            seed nor private_key is provided (seed=42 vulnerability).
        TokenSizeExceededError: if the token exceeds policy.max_token_bytes.
    """
    import json
    from pqblocks_jose.exceptions import InvalidTokenError

    if not isinstance(payload, dict):
        raise InvalidTokenError(f"payload must be a dict, got {type(payload).__name__}")

    if seed is None and private_key is None:
        raise InvalidTokenError("Either 'seed' or 'private_key' must be provided (seed=42 vulnerability fix)")

    protected_header_dict = {"alg": "ML-DSA-65-Ed25519", "typ": "JWT"}
    if kid is not None:
        protected_header_dict["kid"] = kid
    protected_header = json.dumps(protected_header_dict, separators=(",", ":")).encode("utf-8")
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    if private_key is None:
        private_key = generate_keypair("ML-DSA-65-Ed25519", seed=seed).private_key
    compact = sign_jws(payload=payload_bytes, protected_header=protected_header, policy=policy, seed=seed, private_key=private_key)
    # self-check against the public key that belongs to the signing key
    from pqblocks_jose.keypair import public_from_private
    result = verify_jws_with_key(token=compact, policy=policy,
                                 public_key=public_from_private("ML-DSA-65-Ed25519", private_key))
    return JWSResult(
        compact_serialization=result.compact_serialization,
        protected_header=json.loads(result.protected_header),
        payload=json.loads(result.payload),
        algorithm=result.algorithm,
        key_id=result.key_id,
        signature_verified=result.signature_verified,
    )


def decode_jws(
    token: str,
    policy: Policy,
    *,
    public_key: bytes,
    seed: int | None = None,
) -> JWSResult:
    """Decode and verify a hybrid JWS token.

    Args:
        token: Compact JWS serialization string.
        policy: Versioned policy object enforcing constraints.
        public_key: Pre-generated public key bytes for verification (classical||PQ concatenated).
            Required parameter for proper asymmetric verification.
        seed: Deprecated - kept for backward compatibility. If provided without
            public_key, raises InvalidTokenError (seed=42 vulnerability fix).

    Returns:
        JWSResult with structured fields.

    Raises:
        InvalidTokenError: if token is malformed, header is invalid, signature fails,
            or if seed is provided without public_key (seed=42 vulnerability).
        TokenSizeExceededError: if token exceeds policy.max_token_bytes.
    """
    if public_key is None:
        raise InvalidTokenError("public_key is required (seed=42 vulnerability fix - see RFC 7519 §4.1.3)")
    
    if seed is not None:
        key_pair = generate_keypair("ML-DSA-65-Ed25519", seed=seed)
        if key_pair.public_key != public_key:
            raise InvalidTokenError("public_key does not match seed-derived key (attempted forgery check)")
    
    result = verify_jws_with_key(token=token, policy=policy, public_key=public_key)
    return JWSResult(
        compact_serialization=result.compact_serialization,
        protected_header=result.protected_header,
        payload=result.payload,
        algorithm=result.algorithm,
        key_id=result.key_id,
        signature_verified=result.signature_verified,
    )


def encrypt_jwe(
    plaintext: bytes,
    policy: Policy,
    *,
    seed: int | None = None,
    public_key: bytes | None = None,
) -> JWEResult:
    """Encrypt plaintext into a hybrid JWE token (HPKE-X-Wing → AES-256-GCM).

    Uses reference implementation for encryption with seed-based key generation.

    Args:
        plaintext: Bytes to encrypt.
        policy: Versioned policy object enforcing constraints.
        seed: Deterministic seed for key generation. Default 42.
            Only used when public_key is not provided.
        public_key: Optional pre-generated public key bytes. If provided,
            seed is ignored.

    Returns:
        JWEResult with structured fields.

    Raises:
        InvalidTokenError: if plaintext or header is malformed.
        TokenSizeExceededError: if the token exceeds policy.max_token_bytes.
    """
    import hashlib
    import json
    from pqblocks_jose.exceptions import InvalidTokenError

    protected_header = json.dumps(
        {"alg": "HPKE-X25519MLKEM768", "enc": "A256GCM", "typ": "JWT"},
        separators=(",", ":"),
    ).encode("utf-8")

    compact = _ref_encrypt_jwe(
        plaintext=plaintext,
        protected_header=protected_header,
        policy=policy,
        seed=seed,
        public_key=public_key,
    )
    # Describe the token we just built. (This used to "verify" by decrypting
    # with a seed derived from the PUBLIC key - possible only because
    # decryption did not need the private key. It does now.)
    from pqblocks_jose.reference.jwe import _parse_jwe, JsonStr
    header_b, encrypted_key, iv, ciphertext, tag = _parse_jwe(compact)
    header = json.loads(header_b.decode("utf-8"))
    return JWEResult(
        compact_serialization=compact,
        protected_header=JsonStr(header_b.decode("utf-8")),
        plaintext=plaintext,
        algorithm=header.get("alg"),
        enc=header.get("enc"),
        key_id=header.get("kid"),
        iv=iv,
        encrypted_key=encrypted_key,
        ciphertext=ciphertext,
        tag=tag,
    )


def decrypt_jwe(
    token: str,
    policy: Policy,
    *,
    seed: int | None = None,
    public_key: bytes | None = None,
    private_key: bytes | None = None,
) -> JWEResult:
    """Decrypt a hybrid JWE token.

    Args:
        token: Compact JWE serialization string.
        policy: Versioned policy object enforcing constraints.
        seed: Deterministic seed for key generation. Default 42.
            Used only when public_key is not provided.
        public_key: Not accepted for decryption (raises InvalidTokenError):
            a JWE is decrypted with the recipient's private key.
        private_key: Recipient private key bytes (x25519_sk || ml_kem_768_seed).

    Returns:
        JWEResult with structured fields including recovered plaintext.

    Raises:
        InvalidTokenError: if token is malformed.
        DecryptionError: if decapsulation or AES-GCM decryption fails.
        TokenSizeExceededError: if token exceeds policy.max_token_bytes.
    """
    # private_key (x25519_sk || ml_kem_768_seed) or seed. A public key alone
    # is refused: decryption with a public key would mean anyone can decrypt.
    result = _ref_decrypt_jwe(token=token, policy=policy, seed=seed,
                              public_key=public_key, private_key=private_key)
    return JWEResult(
        compact_serialization=result.compact_serialization,
        protected_header=result.protected_header,
        plaintext=result.plaintext,
        algorithm=result.algorithm,
        enc=result.enc,
        key_id=result.key_id,
        iv=result.iv,
        encrypted_key=result.encrypted_key,
        ciphertext=result.ciphertext,
        tag=result.tag,
    )
