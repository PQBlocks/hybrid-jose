"""Reference implementation for JWE: HPKE-X-Wing -> A256GCM.

Pure-Python reference oracle per spec Algorithm section 1.3
(pqblocks-jose spec/spec.md). Classical primitives come from the audited
``cryptography`` library (X25519, AES-256-GCM, HKDF-SHA256); ML-KEM-768 is
pyca/cryptography's (via pqblocks_jose.pq), combined with the X-Wing combiner
(draft-connolly-cfrg-xwing-kem 5.3). Key/ciphertext ORDER is this product's
(classical first), so tokens are not wire-compatible with X-Wing itself.

Determinism applies to KEY GENERATION only: every encryption uses a fresh
ephemeral key and nonce - a seed-derived nonce repeated AES-GCM key+nonce.
"""

import base64
import os
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pqblocks_jose.exceptions import (
    DecryptionError,
    InvalidTokenError,
    PolicyMismatchError,
    TokenSizeExceededError,
)
from pqblocks_jose import pq
from pqblocks_jose.policy import Policy


CANONICAL_KDF = "HKDF-SHA256"
CANONICAL_KDF_INFO = "JOSE_PostQuantum_Traditional_Hybrid X25519MLKEM768"
SUPPORTED_POLICY_VERSIONS = (1, 2)
EXPECTED_ALG = "HPKE-X25519MLKEM768"
EXPECTED_ENC = "A256GCM"

_MASK64 = 0xFFFFFFFFFFFFFFFF


class _SplitMix64:
    """SplitMix64 DRBG (Steele et al.). Seeded named streams ."""

    def __init__(self, seed: int) -> None:
        self.state = int(seed) & _MASK64

    def next_u64(self) -> int:
        self.state = (self.state + 0x9E3779B97F4A7C15) & _MASK64
        z = self.state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & _MASK64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & _MASK64
        return (z ^ (z >> 31)) & _MASK64

    def next_bytes(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            out += self.next_u64().to_bytes(8, "little")
        return bytes(out[:n])


def _stream_bytes(seed: int, label: bytes, n: int) -> bytes:
    """Derive ``n`` deterministic bytes for a named stream."""
    tag = hashlib.sha256(b"pqblocks-jose-jwe-v1:" + label).digest()
    mixed = (int(seed) ^ int.from_bytes(tag[:8], "little")) & _MASK64
    return _SplitMix64(mixed).next_bytes(n)


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


@dataclass(frozen=True)
class JWEResult:
    """Structured result from JWE operations."""

    compact_serialization: str
    protected_header: Any
    plaintext: bytes
    algorithm: str
    enc: str
    key_id: Optional[str]
    iv: bytes
    encrypted_key: bytes
    ciphertext: bytes
    tag: bytes


_DEFAULT_SEED = b"pqblocks-jose-reference-seed-v1"


def _check_policy(policy: Policy) -> None:
    """Validate the policy object against the fixed spec parameters (section 2)."""
    if policy.kdf != CANONICAL_KDF:
        raise PolicyMismatchError(
            f"Unsupported kdf {policy.kdf!r}; expected {CANONICAL_KDF!r}"
        )
    if policy.kdf_info != CANONICAL_KDF_INFO:
        raise PolicyMismatchError(
            f"Policy kdf_info mismatch: {policy.kdf_info!r} != canonical"
        )
    if policy.version not in SUPPORTED_POLICY_VERSIONS:
        raise PolicyMismatchError(
            f"Unsupported policy version {policy.version!r}; "
            f"supported {list(SUPPORTED_POLICY_VERSIONS)}"
        )


def _derive_x25519_keypair(seed: int, label: bytes):
    """Derive a deterministic X25519 keypair from a seeded stream."""
    priv_bytes = _stream_bytes(seed, label, 32)
    private_key = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
    return private_key, private_key.public_key()


def _base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(data: str) -> bytes:
    """Decode base64url string to bytes, adding padding if needed."""
    if not isinstance(data, str):
        raise InvalidTokenError("Data to decode must be a string")
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    try:
        return base64.b64decode(data.encode("ascii"), altchars=b"-_", validate=True)
    except Exception as e:
        raise InvalidTokenError(f"Base64url decoding failed: {str(e)}")


def _parse_jwe(compact_jwe: str) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    """Parse compact JWE into its 5 components."""
    parts = compact_jwe.split(".")
    if len(parts) != 5:
        raise InvalidTokenError("Invalid JWE structure: must have 5 parts")

    protected_header_b64 = parts[0]
    encrypted_key_b64 = parts[1]
    iv_b64 = parts[2]
    ciphertext_b64 = parts[3]
    tag_b64 = parts[4]

    protected_header = _base64url_decode(protected_header_b64)
    encrypted_key = _base64url_decode(encrypted_key_b64)
    iv = _base64url_decode(iv_b64)
    ciphertext = _base64url_decode(ciphertext_b64)
    tag = _base64url_decode(tag_b64)

    return protected_header, encrypted_key, iv, ciphertext, tag


# ML-KEM-768 is real (pyca/cryptography via pqblocks_jose.pq). Until 2026-10-07
# this module simulated it, derived the "decryption" key from the PUBLIC key,
# and derived the ephemeral key and AES-GCM nonce from the seed (key/nonce reuse).


def encrypt_jwe(
    plaintext: bytes,
    protected_header: bytes,
    policy: Policy,
    seed: int | None = None,
    public_key: bytes | None = None,
) -> str:
    """Encrypt a JWE token using HPKE-X-Wing -> A256GCM (spec section 1.3).
    
    Args:
        plaintext: The plaintext bytes to encrypt.
        protected_header: The JWS protected header bytes.
        policy: The policy object containing constraints.
        seed: Deterministic seed for key generation. Required if
            public_key is not provided. Omitting seed without public_key
            raises InvalidTokenError to prevent seed=42 forgery vulnerability.
        public_key: Optional pre-generated public key for encryption.
            When provided, seed is ignored.
    """

    if seed is None and public_key is None:
        raise InvalidTokenError("Either 'seed' or 'public_key' must be provided (seed=42 vulnerability fix)")
    if not isinstance(plaintext, bytes) or not isinstance(protected_header, bytes):
        raise InvalidTokenError("Plaintext and protected header must be bytes")

    _check_policy(policy)

    if not isinstance(plaintext, bytes) or not isinstance(protected_header, bytes):
        raise InvalidTokenError("Plaintext and protected header must be bytes")

    try:
        protected_header_dict = json.loads(protected_header.decode("utf-8"))
        if not isinstance(protected_header_dict, dict):
            raise InvalidTokenError("Protected header must be a JSON object")
    except InvalidTokenError:
        raise
    except Exception as e:
        raise InvalidTokenError(f"Malformed protected header: {str(e)}")

    # Encrypt to the recipient's PUBLIC key: x25519_pk(32B) || ml_kem_768_pk(1184B),
    # given directly or derived from the seed. Ephemeral key and nonce are
    # fresh every call - determinism belongs to key generation, never encryption.
    if public_key is None:
        from pqblocks_jose.keypair import generate_keypair as _gk
        public_key = _gk("X25519+MLKEM768", seed=seed).public_key
    if len(public_key) != 1216:
        raise InvalidTokenError(f"Invalid recipient public key length: {len(public_key)} != 1216")
    ss_xwing, ct_cl, ct_pq = pq.hybrid_encapsulate(public_key[:32], public_key[32:1216])
    ct_xwing = ct_cl + ct_pq

    cek = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",
        info=policy.kdf_info.encode("utf-8"),
    ).derive(ss_xwing)

    nonce = os.urandom(12)

    aad = _base64url_encode(protected_header).encode("utf-8")

    aesgcm = AESGCM(cek)
    ciphertext_tag = aesgcm.encrypt(nonce, plaintext, aad)
    ciphertext, tag = ciphertext_tag[:-16], ciphertext_tag[-16:]

    compact_serialization = (
        f"{_base64url_encode(protected_header)}.{_base64url_encode(ct_xwing)}."
        f"{_base64url_encode(nonce)}.{_base64url_encode(ciphertext)}."
        f"{_base64url_encode(tag)}"
    )

    token_size = len(compact_serialization.encode("utf-8"))
    if token_size > policy.max_token_bytes:
        raise TokenSizeExceededError(token_size, policy.max_token_bytes)

    return compact_serialization


def decrypt_jwe(
    token: str,
    policy: Policy,
    seed: int | None = None,
    public_key: bytes | None = None,
    private_key: bytes | None = None,
) -> JWEResult:
    """Decrypt a JWE token using HPKE-X-Wing -> A256GCM (spec section 1.3).
    
    Args:
        token: The compact JWE serialization string.
        policy: The policy object containing constraints.
        seed: Deterministic seed for key generation. Required if
            public_key is not provided. Raises InvalidTokenError if None.
        public_key: Optional pre-generated public key for decryption.
            When provided, seed is ignored.
    """

    if not isinstance(token, str):
        raise InvalidTokenError("Token must be a string")

    _check_policy(policy)

    try:
        protected_header, encrypted_key, iv, ciphertext, tag = _parse_jwe(token)
    except (InvalidTokenError, TokenSizeExceededError):
        raise
    except Exception as e:
        raise InvalidTokenError(f"Malformed JWE: {str(e)}")

    token_size = len(token.encode("utf-8"))
    if token_size > policy.max_token_bytes:
        raise TokenSizeExceededError(token_size, policy.max_token_bytes)

    if len(iv) != 12:
        raise InvalidTokenError(f"Invalid nonce length: {len(iv)} != 12")
    if len(tag) != 16:
        raise InvalidTokenError(f"Invalid tag length: {len(tag)} != 16")

    try:
        protected_header_dict = json.loads(protected_header.decode("utf-8"))
        if not isinstance(protected_header_dict, dict):
            raise InvalidTokenError("Protected header must be a JSON object")
        algorithm = protected_header_dict.get("alg", "unknown")
        enc = protected_header_dict.get("enc", "unknown")
        if algorithm != EXPECTED_ALG:
            raise InvalidTokenError(f"Unsupported algorithm: {algorithm}")
        if enc != EXPECTED_ENC:
            raise InvalidTokenError(f"Unsupported encryption algorithm: {enc}")
        key_id = protected_header_dict.get("kid")
    except InvalidTokenError:
        raise
    except Exception as e:
        raise InvalidTokenError(f"Failed to parse protected header: {str(e)}")

    # Decryption needs the recipient's PRIVATE key: x25519_sk(32B) ||
    # ml_kem_768_seed(64B), given directly or derived from the seed.
    if private_key is None:
        if seed is None:
            raise InvalidTokenError("JWE decryption requires the recipient's private key (or seed); "
                                    "a public key cannot decrypt")
        from pqblocks_jose.keypair import generate_keypair as _gk
        private_key = _gk("X25519+MLKEM768", seed=seed).private_key
    if len(private_key) != 96:
        raise InvalidTokenError(f"Invalid recipient private key length: {len(private_key)} != 96")

    if len(encrypted_key) != 1120:
        raise DecryptionError(
            f"Invalid encrypted key length: {len(encrypted_key)} != 1120"
        )

    ct_cl = encrypted_key[:32]
    ct_pq = encrypted_key[32:]
    try:
        ss_xwing = pq.hybrid_decapsulate(private_key[:32], private_key[32:96], ct_cl, ct_pq)
    except Exception as e:
        raise DecryptionError("JWE decryption failed")      # one uniform error for every failure cause

    cek = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",
        info=policy.kdf_info.encode("utf-8"),
    ).derive(ss_xwing)

    aad = _base64url_encode(protected_header).encode("utf-8")

    try:
        aesgcm = AESGCM(cek)
        plaintext = aesgcm.decrypt(iv, ciphertext + tag, aad)
    except Exception as e:
        raise DecryptionError("JWE decryption failed")

    return JWEResult(
        compact_serialization=token,
        protected_header=JsonStr(protected_header.decode("utf-8")),
        plaintext=plaintext,
        algorithm=algorithm,
        enc=enc,
        key_id=key_id,
        iv=iv,
        encrypted_key=encrypted_key,
        ciphertext=ciphertext,
        tag=tag,
    )
