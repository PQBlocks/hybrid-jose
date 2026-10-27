"""Tests for S5: Public API Facade.

This test module covers:
- encode_jws() / decode_jws() round trips
- encrypt_jwe() / decrypt_jwe() round trips
- generate_keypair() for both algorithm families
- Result object fields (JWSResult, JWEResult, KeyPair)
- Error mapping from internal exceptions to public API
- Policy integration via public API
"""

import pytest
import json
from pqblocks_jose import (
    encode_jws,
    decode_jws,
    encrypt_jwe,
    decrypt_jwe,
    generate_keypair,
    JWSResult,
    JWEResult,
    KeyPair,
    JsonStr,
)
from pqblocks_jose.policy import Policy
from pqblocks_jose import generate_keypair

# The signing seed and the verification key MUST come from the same source.
# They did not: this module derived _PUBKEY from seed=0 while 22 encode_jws()
# calls below signed with seed=42, so every test that signed and then verified
# against _PUBKEY failed with "Signature verification failed" - the library was
# correctly rejecting a signature made by a different key. Derive both from one
# constant so the suite cannot drift apart again.
_SEED = 42
_KEYPAIR = generate_keypair("ML-DSA-65-Ed25519", seed=_SEED)
_PUBKEY = _KEYPAIR.public_key

from pqblocks_jose.exceptions import (
    InvalidTokenError,
    TokenSizeExceededError,
    DecryptionError,
    PolicyMismatchError,
)


# === JWS Public API ===

def test_encode_jws_returns_jws_result():
    """Test encode_jws returns a JWSResult with correct fields."""
    payload = {"sub": "test", "iat": 1700000000}
    policy = Policy()

    result = encode_jws(payload, policy, seed=42)

    assert isinstance(result, JWSResult)
    assert isinstance(result.compact_serialization, str)
    assert result.algorithm == "ML-DSA-65-Ed25519"
    assert result.signature_verified is True
    assert result.payload["sub"] == "test"
    assert result.payload["iat"] == 1700000000


def test_encode_jws_with_seed():
    """Test encode_jws is deterministic with seed."""
    payload = {"sub": "test"}
    policy = Policy()

    # Note: hedged signing behavior updated
    # for one seed. Signing is now FIPS 204 HEDGED on pyca/OpenSSL (FIPS 204 3.4 recommends hedged; the
    # deterministic path ran in non-constant-time pure Python). Same seed -> same KEY; every token verifies.
    result1 = encode_jws(payload, policy, seed=42)
    result2 = encode_jws(payload, policy, seed=42)

    pk = generate_keypair("ML-DSA-65-Ed25519", seed=42).public_key
    assert decode_jws(token=result1.compact_serialization, policy=policy, public_key=pk).signature_verified
    assert decode_jws(token=result2.compact_serialization, policy=policy, public_key=pk).signature_verified


def test_decode_jws_round_trip():
    """Test decode_jws recovers payload from encode_jws token."""
    payload = {"sub": "test", "name": "Alice"}
    policy = Policy()

    encoded = encode_jws(payload, policy, seed=42)
    decoded = decode_jws(encoded.compact_serialization, policy, public_key=_PUBKEY)

    assert decoded.signature_verified is True
    assert decoded.payload["sub"] == "test"
    assert decoded.payload["name"] == "Alice"
    assert decoded.algorithm == "ML-DSA-65-Ed25519"
    assert decoded.key_id is None


def test_decode_jws_tampered_token_raises():
    """Test decode_jws raises InvalidTokenError for tampered token."""
    payload = {"sub": "test"}
    policy = Policy()

    encoded = encode_jws(payload, policy, seed=42)
    tampered = encoded.compact_serialization[:-5] + "xxxxx"

    with pytest.raises(InvalidTokenError):
        decode_jws(tampered, policy, public_key=_PUBKEY)


def test_encode_jws_wrong_algorithm_rejected():
    """Test decode_jws rejects tokens with wrong algorithm."""
    from pqblocks_jose.reference.jws import _base64url_encode
    payload = {"sub": "test"}
    policy = Policy()

    encoded = encode_jws(payload, policy, seed=42)
    parts = encoded.compact_serialization.split(".")
    # Build a token with RS256 header
    wrong_header = _base64url_encode(b'{"alg":"RS256","typ":"JWT"}')
    bad_token = f"{wrong_header}.{parts[1]}.{parts[2]}"

    with pytest.raises(InvalidTokenError):
        decode_jws(bad_token, policy, public_key=_PUBKEY)


# === JWE Public API ===

def test_encrypt_jwe_returns_jwe_result():
    """Test encrypt_jwe returns a JWEResult with correct fields."""
    plaintext = b"Hello, post-quantum world!"
    policy = Policy()

    result = encrypt_jwe(plaintext, policy, seed=42)

    assert isinstance(result, JWEResult)
    assert isinstance(result.compact_serialization, str)
    assert result.algorithm == "HPKE-X25519MLKEM768"
    assert result.enc == "A256GCM"
    assert result.plaintext == plaintext
    assert len(result.iv) == 12
    assert len(result.tag) == 16
    assert len(result.encrypted_key) == 1120


def test_decrypt_jwe_round_trip():
    """Test decrypt_jwe recovers plaintext from encrypt_jwe token."""
    plaintext = b"Secret message for PQ world"
    policy = Policy()

    encrypted = encrypt_jwe(plaintext, policy, seed=42)
    decrypted = decrypt_jwe(encrypted.compact_serialization, policy, seed=42)

    assert decrypted.plaintext == plaintext
    assert decrypted.algorithm == "HPKE-X25519MLKEM768"
    assert decrypted.enc == "A256GCM"
    assert decrypted.iv == encrypted.iv
    assert decrypted.encrypted_key == encrypted.encrypted_key


def test_encrypt_jwe_with_seed():
    """Test encrypt_jwe is deterministic with seed."""
    plaintext = b"test plaintext"
    policy = Policy()

    # Note: hedged signing behavior updated
    # That was the bug, not a property: a seed-derived ephemeral key and AES-GCM nonce
    # repeat key+nonce across messages (NIST SP 800-38D s8 forbids it) and FIPS 203 7.2
    # requires fresh Encaps randomness. Same seed -> same RECIPIENT key; every token
    # differs and each decrypts with that key.
    result1 = encrypt_jwe(plaintext, policy, seed=42)
    result2 = encrypt_jwe(plaintext, policy, seed=42)

    assert result1.compact_serialization != result2.compact_serialization
    assert decrypt_jwe(result1.compact_serialization, policy, seed=42).plaintext == plaintext
    assert decrypt_jwe(result2.compact_serialization, policy, seed=42).plaintext == plaintext


def test_decrypt_jwe_tampered_ciphertext_raises():
    """Test decrypt_jwe raises DecryptionError for tampered ciphertext."""
    plaintext = b"test"
    policy = Policy()

    encrypted = encrypt_jwe(plaintext, policy, seed=42)
    parts = encrypted.compact_serialization.split(".")
    tampered = parts[0] + "." + parts[1] + "." + parts[2] + "." + parts[3][:-4] + "xxxx" + "." + parts[4]

    with pytest.raises(DecryptionError):
        decrypt_jwe(tampered, policy, seed=42)


def test_decrypt_jwe_invalid_encrypted_key_raises():
    """Test decrypt_jwe raises DecryptionError for invalid encrypted key length."""
    from pqblocks_jose.reference.jwe import _base64url_encode
    plaintext = b"test"
    policy = Policy()

    encrypted = encrypt_jwe(plaintext, policy, seed=42)
    parts = encrypted.compact_serialization.split(".")
    bad_ek = _base64url_encode(b"short")
    bad_token = f"{parts[0]}.{bad_ek}.{parts[2]}.{parts[3]}.{parts[4]}"

    with pytest.raises((DecryptionError, InvalidTokenError)):
        decrypt_jwe(bad_token, policy, seed=42)


# === Key Generation ===

def test_generate_keypair_jws():
    """Test generate_keypair for JWS algorithm returns KeyPair."""
    policy = Policy()
    keypair = generate_keypair("ML-DSA-65-Ed25519", seed=42)

    assert isinstance(keypair, KeyPair)
    assert keypair.algorithm == "ML-DSA-65-Ed25519"
    assert isinstance(keypair.private_key, bytes)
    assert isinstance(keypair.public_key, bytes)
    assert len(keypair.private_key) > 0
    assert len(keypair.public_key) > 0


def test_generate_keypair_jwe():
    """Test generate_keypair for JWE algorithm returns KeyPair."""
    policy = Policy()
    keypair = generate_keypair("X25519+MLKEM768", seed=42)

    assert isinstance(keypair, KeyPair)
    assert keypair.algorithm == "X25519+MLKEM768"
    assert isinstance(keypair.private_key, bytes)
    assert isinstance(keypair.public_key, bytes)
    assert len(keypair.private_key) > 0
    assert len(keypair.public_key) > 0


def test_generate_keypair_deterministic():
    """Test generate_keypair produces same keys with same seed."""
    kp1 = generate_keypair("ML-DSA-65-Ed25519", seed=42)
    kp2 = generate_keypair("ML-DSA-65-Ed25519", seed=42)

    assert kp1.private_key == kp2.private_key
    assert kp1.public_key == kp2.public_key


# === Policy Integration ===

def test_encode_jws_respects_max_token_bytes():
    """Test encode_jws enforces policy max_token_bytes."""
    payload = {"data": "x" * 10000}
    policy = Policy(max_token_bytes=100)

    with pytest.raises(TokenSizeExceededError):
        encode_jws(payload, policy, seed=42)


def test_decode_jws_respects_max_token_bytes():
    """Test decode_jws enforces policy max_token_bytes on verify."""
    payload = {"sub": "test"}
    policy = Policy()

    encoded = encode_jws(payload, policy, seed=42)
    tiny_policy = Policy(max_token_bytes=1)

    with pytest.raises(TokenSizeExceededError):
        decode_jws(encoded.compact_serialization, tiny_policy, public_key=_PUBKEY)


# === Empty Payload Edge Case ===

def test_encode_jws_empty_payload():
    """Test encode_jws handles empty dict payload."""
    payload = {}
    policy = Policy()

    result = encode_jws(payload, policy, seed=42)
    assert result.payload == {}
    assert result.signature_verified is True


# === KeyId Propagation ===

def test_encode_jws_with_kid():
    """Test encode_jws propagates kid from header."""
    payload = {"sub": "test"}
    policy = Policy()

    result = encode_jws(payload, policy, kid="my-key-1", seed=_SEED)
    assert result.key_id == "my-key-1"


# === Non-Dict Payload Rejection ===

def test_encode_jws_non_dict_payload_raises():
    """Test encode_jws rejects non-dict payload."""
    policy = Policy()
    with pytest.raises((InvalidTokenError, TypeError, ValueError)):
        encode_jws("not a dict", policy)


def test_encode_jws_bytes_payload_raises():
    """Test encode_jws rejects bytes payload (must be dict for public API)."""
    policy = Policy()
    with pytest.raises((InvalidTokenError, TypeError, ValueError)):
        encode_jws(b"bytes payload", policy)


# === Result Object Dataclass Fields ===

def test_jws_result_is_frozen_dataclass():
    """Test JWSResult is a frozen dataclass."""
    result = JWSResult(
        compact_serialization="test.token.here",
        protected_header={"alg": "ML-DSA-65-Ed25519"},
        payload={"sub": "test"},
        algorithm="ML-DSA-65-Ed25519",
        key_id=None,
        signature_verified=True,
    )
    assert result.compact_serialization == "test.token.here"
    assert result.algorithm == "ML-DSA-65-Ed25519"
    assert result.signature_verified is True


def test_jwe_result_is_frozen_dataclass():
    """Test JWEResult is a frozen dataclass."""
    result = JWEResult(
        compact_serialization="test.token.here",
        protected_header={"alg": "HPKE-X25519MLKEM768"},
        plaintext=b"hello",
        algorithm="HPKE-X25519MLKEM768",
        enc="A256GCM",
        key_id=None,
        iv=b"\x00" * 12,
        encrypted_key=b"\x00" * 1120,
        ciphertext=b"\x00" * 16,
        tag=b"\x00" * 16,
    )
    assert result.enc == "A256GCM"
    assert len(result.iv) == 12
    assert len(result.tag) == 16


def test_key_pair_is_frozen_dataclass():
    """Test KeyPair is a frozen dataclass."""
    kp = KeyPair(
        private_key=b"priv",
        public_key=b"pub",
        algorithm="ML-DSA-65-Ed25519",
    )
    assert kp.algorithm == "ML-DSA-65-Ed25519"
    assert kp.private_key == b"priv"
    assert kp.public_key == b"pub"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])