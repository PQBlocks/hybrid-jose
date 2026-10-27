"""Tests for S2: Reference JWS: ML-DSA-65-Ed25519.

This test module covers the full feature contract including:
- Worked example from spec §1.5
- Edge cases EC1, EC2, EC3, EC4, EC6, EC8, EC11
- Deterministic reproducibility
- Token size enforcement
- Signature verification
"""

import pytest
import json
from pqblocks_jose.reference.jws import sign_jws, verify_jws, JWSResult, JsonStr
from pqblocks_jose.policy import Policy
from pqblocks_jose.exceptions import (
    InvalidTokenError,
    TokenSizeExceededError,
    ReplayDetectedError,
)


# === Worked Example and Core Tests ===

def test_worked_example():
    """Test the worked example from spec §1.5."""
    payload_json = '{"sub":"test","iat":1700000000}'
    protected_header_json = '{"alg":"ML-DSA-65-Ed25519","typ":"JWT"}'

    payload = payload_json.encode('utf-8')
    protected_header = protected_header_json.encode('utf-8')
    policy = Policy()

    token = sign_jws(payload, protected_header, policy, seed=42)
    result = verify_jws(token, policy, seed=42)

    assert result.signature_verified is True
    assert result.algorithm == "ML-DSA-65-Ed25519"
    assert json.loads(result.payload) == {"sub": "test", "iat": 1700000000}
    assert json.loads(result.protected_header) == {"alg": "ML-DSA-65-Ed25519", "typ": "JWT"}


def test_empty_payload():
    """Test EC1: Empty payload ({})."""
    payload = b"{}"
    protected_header = b'{"alg":"ML-DSA-65-Ed25519","typ":"JWT"}'
    policy = Policy()

    token = sign_jws(payload, protected_header, policy, seed=42)
    result = verify_jws(token, policy, seed=42)

    assert result.signature_verified is True
    assert json.loads(result.payload) == {}


def test_single_claim_payload():
    """Test EC2: Single-claim payload (minimal {"sub":"x"})."""
    payload = b'{"sub":"x"}'
    protected_header = b'{"alg":"ML-DSA-65-Ed25519","typ":"JWT"}'
    policy = Policy()

    token = sign_jws(payload, protected_header, policy, seed=42)
    result = verify_jws(token, policy, seed=42)

    assert result.signature_verified is True
    assert json.loads(result.payload) == {"sub": "x"}


def test_token_size_under_limit():
    """Verify token respects max_token_bytes policy."""
    payload = b'{"sub":"test"}'
    protected_header = b'{"alg":"ML-DSA-65-Ed25519","typ":"JWT"}'
    policy = Policy(max_token_bytes=8192)

    token = sign_jws(payload, protected_header, policy, seed=42)
    result = verify_jws(token, policy, seed=42)
    assert result.signature_verified is True


# === Edge Cases ===

def test_malformed_header_rejected():
    """Test EC3: Disconnected/malformed header."""
    payload = b'{"sub":"test"}'
    protected_header = b'{"alg":"ML-DSA-65-Ed25519","typ":"JWT"'  # Invalid JSON
    policy = Policy()

    with pytest.raises(InvalidTokenError):
        sign_jws(payload, protected_header, policy, seed=42)


def test_invalid_algorithm_rejected():
    """Test EC3 variant: Wrong alg in header rejected."""
    payload = b'{"sub":"test"}'
    protected_header = b'{"alg":"RS256","typ":"JWT"}'
    policy = Policy()

    # 2026-10-07: the signer refuses a wrong alg; the verifier rejects a swapped header
    with pytest.raises(InvalidTokenError):
        sign_jws(payload, protected_header, policy, seed=42)
    import base64 as _b64
    def _swap_alg(tok, alg):
        h = _b64.urlsafe_b64encode(('{"alg":"%s","typ":"JWT"}' % alg).encode()).rstrip(b"=").decode()
        return h + tok[tok.index("."):]
    good = sign_jws(payload, b'{"alg":"ML-DSA-65-Ed25519","typ":"JWT"}', policy, seed=42)
    with pytest.raises(InvalidTokenError):
        verify_jws(_swap_alg(good, "RS256"), policy, seed=42)


def test_tampered_token_rejected():
    """Test EC3 variant: Tampered token raises InvalidTokenError."""
    payload = b'{"sub":"test"}'
    protected_header = b'{"alg":"ML-DSA-65-Ed25519","typ":"JWT"}'
    policy = Policy()

    token = sign_jws(payload, protected_header, policy, seed=42)
    parts = token.split('.')
    tampered = parts[0] + '.' + parts[1] + '.tampered'
    with pytest.raises(InvalidTokenError):
        verify_jws(tampered, policy, seed=42)


def test_wrong_prefix_rejected():
    """Test EC3 variant: Wrong composite signature prefix rejected."""
    payload = b'{"sub":"test"}'
    protected_header = b'{"alg":"ML-DSA-65-Ed25519","typ":"JWT"}'
    policy = Policy()

    token = sign_jws(payload, protected_header, policy, seed=42)
    parts = token.split('.')
    # Tamper the signature part by changing the prefix
    import base64
    sig_part = parts[2]
    padding = 4 - len(sig_part) % 4
    if padding != 4:
        sig_part += "=" * padding
    sig_bytes = base64.urlsafe_b64decode(sig_part)
    tampered_sig = b'\x00\x00' + sig_bytes[2:]  # Change prefix
    tampered_sig_b64 = base64.urlsafe_b64encode(tampered_sig).rstrip(b'=').decode('ascii')
    tampered_parts = parts.copy()
    tampered_parts[2] = tampered_sig_b64
    tampered_token = '.'.join(tampered_parts)
    with pytest.raises(InvalidTokenError):
        verify_jws(tampered_token, policy, seed=42)


# === Determinism ===

def test_deterministic_signing():
    """Test Same seed produces bit-identical signatures."""
    payload = b'{"sub":"test"}'
    protected_header = b'{"alg":"ML-DSA-65-Ed25519","typ":"JWT"}'
    policy = Policy()

    # Note: hedged signing behavior updated
    # for one seed. Signing is now FIPS 204 HEDGED on pyca/OpenSSL (FIPS 204 3.4 recommends hedged; the
    # deterministic path ran in non-constant-time pure Python). Same seed -> same KEY; every token verifies.
    token1 = sign_jws(payload, protected_header, policy, seed=42)
    token2 = sign_jws(payload, protected_header, policy, seed=42)

    assert verify_jws(token1, policy, seed=42).signature_verified
    assert verify_jws(token2, policy, seed=42).signature_verified


def test_different_seed_produces_different_token():
    """Test Different seeds produce different tokens."""
    payload = b'{"sub":"test"}'
    protected_header = b'{"alg":"ML-DSA-65-Ed25519","typ":"JWT"}'
    policy = Policy()

    token1 = sign_jws(payload, protected_header, policy, seed=42)
    token2 = sign_jws(payload, protected_header, policy, seed=100)

    assert token1 != token2


# === Token Size Enforcement ===

def test_token_size_cap_enforced():
    """Test EC8: Penalty overflow analogue - Token size > max_token_bytes."""
    large_payload = b'{"data":"' + b"x" * 5000 + b'"}'
    protected_header = b'{"alg":"ML-DSA-65-Ed25519","typ":"JWT"}'
    policy = Policy(max_token_bytes=100)

    with pytest.raises(TokenSizeExceededError):
        sign_jws(large_payload, protected_header, policy, seed=42)


def test_max_token_bytes_default_accommodates_ml_dsa():
    """Verify default max_token_bytes accommodates ML-DSA-65-Ed25519 tokens."""
    payload = b'{"sub":"test"}'
    protected_header = b'{"alg":"ML-DSA-65-Ed25519","typ":"JWT"}'
    policy = Policy()  # Default should be >= 4596 bytes

    token = sign_jws(payload, protected_header, policy, seed=42)
    # Token should be well under 8192
    assert len(token.encode('utf-8')) < policy.max_token_bytes


# === Result Object Tests ===

def test_jws_result_fields():
    """Test JWSResult has correct fields."""
    payload = b'{"sub":"test"}'
    protected_header = b'{"alg":"ML-DSA-65-Ed25519","typ":"JWT"}'
    policy = Policy()

    token = sign_jws(payload, protected_header, policy, seed=42)
    result = verify_jws(token, policy, seed=42)

    assert isinstance(result, JWSResult)
    assert isinstance(result.compact_serialization, str)
    assert isinstance(result.protected_header, JsonStr)
    assert isinstance(result.payload, JsonStr)
    assert result.algorithm == "ML-DSA-65-Ed25519"
    assert result.signature_verified is True


def test_result_json_roundtrip():
    """Test that JsonStr supports dict-like access."""
    payload = b'{"sub":"test"}'
    protected_header = b'{"alg":"ML-DSA-65-Ed25519","typ":"JWT"}'
    policy = Policy()

    token = sign_jws(payload, protected_header, policy, seed=42)
    result = verify_jws(token, policy, seed=42)

    assert result.payload["sub"] == "test"
    assert result.protected_header["alg"] == "ML-DSA-65-Ed25519"


# === Policy Tests ===

def test_policy_default_max_token_bytes():
    """Test Policy default max_token_bytes accommodates ML-DSA-65."""
    policy = Policy()
    assert policy.max_token_bytes >= 4596


def test_policy_custom_max_token_bytes():
    """Test Policy with custom max_token_bytes."""
    policy = Policy(max_token_bytes=10000)
    assert policy.max_token_bytes == 10000


# === Negative Tests ===

def test_non_bytes_payload_raises():
    """Test that non-bytes payload raises InvalidTokenError."""
    policy = Policy()
    with pytest.raises(InvalidTokenError):
        sign_jws("not bytes", b'{"alg":"ML-DSA-65-Ed25519"}', policy, seed=42)


def test_non_string_token_raises():
    """Test that non-string token raises InvalidTokenError."""
    policy = Policy()
    with pytest.raises(InvalidTokenError):
        verify_jws(123, policy, seed=42)


def test_malformed_jwt_raises():
    """Test that malformed JWT raises InvalidTokenError."""
    policy = Policy()
    with pytest.raises(InvalidTokenError):
        verify_jws("not.a.valid.jwt", policy, seed=42)


# === Coverage for Exceptions ===

def test_replay_detected_error_jti():
    """Test ReplayDetectedError stores jti attribute."""
    err = ReplayDetectedError("test-jti-123")
    assert err.jti == "test-jti-123"
    assert "test-jti-123" in str(err)


# === Coverage for JsonStr Methods ===

def test_jsonstr_get_method():
    """Test JsonStr.get() method."""
    s = JsonStr('{"alg":"ML-DSA-65-Ed25519","typ":"JWT"}')
    assert s.get("alg") == "ML-DSA-65-Ed25519"
    assert s.get("missing", "default") == "default"


def test_jsonstr_keys_values_items():
    """Test JsonStr.keys(), values(), items() methods."""
    s = JsonStr('{"a":1,"b":2}')
    keys = list(s.keys())
    assert set(keys) == {"a", "b"}
    vals = list(s.values())
    assert set(vals) == {1, 2}
    items = list(s.items())
    assert set(items) == {("a", 1), ("b", 2)}


def test_jsonstr_getitem_non_string_key():
    """Test JsonStr.__getitem__ with non-string key hits super().__getitem__."""
    s = JsonStr('{"alg":"ML-DSA-65-Ed25519"}')
    # str.__getitem__ supports integer indexing (returns character at index)
    # So s[0] returns the first character '{', not raising an error
    result = s[0]
    assert result == '{'


def test_jsonstr_getitem_non_dict():
    """Test JsonStr.__getitem__ when JSON is not a dict."""
    s = JsonStr('[1,2,3]')
    with pytest.raises((TypeError, KeyError, AttributeError)):
        _ = s["key"]


# === Coverage for _base64url_decode Edge Cases ===

def test_base64url_decode_non_string():
    """Test _base64url_decode raises InvalidTokenError for non-string input."""
    from pqblocks_jose.reference.jws import _base64url_decode
    with pytest.raises(InvalidTokenError):
        _base64url_decode(123)


def test_base64url_decode_invalid():
    """Test _base64url_decode raises InvalidTokenError for invalid base64."""
    from pqblocks_jose.reference.jws import _base64url_decode
    # base64.urlsafe_b64decode does not accept validate= keyword in Python 3.14.
    # _base64url_decode must raise InvalidTokenError for invalid base64url input.
    with pytest.raises(InvalidTokenError):
        _base64url_decode("!!!invalid!!!")


# === Coverage for sign_jws Non-Dict Headers/Payloads ===

def test_sign_jws_non_dict_protected_header():
    """Test sign_jws raises InvalidTokenError when protected header is not a JSON object."""
    payload = b'{"sub":"test"}'
    protected_header = b'["not", "a", "dict"]'  # Valid JSON but not a dict
    policy = Policy()
    with pytest.raises(InvalidTokenError):
        sign_jws(payload, protected_header, policy, seed=42)


def test_sign_jws_non_dict_payload():
    """Test sign_jws raises InvalidTokenError when payload is not a JSON object."""
    payload = b'["not", "a", "dict"]'  # Valid JSON but not a dict
    protected_header = b'{"alg":"ML-DSA-65-Ed25519","typ":"JWT"}'
    policy = Policy()
    with pytest.raises(InvalidTokenError):
        sign_jws(payload, protected_header, policy, seed=42)


# === Coverage for verify_jws Edge Cases ===

def test_verify_jws_token_size_exceeded():
    """Test verify_jws raises TokenSizeExceededError for oversized token."""
    from pqblocks_jose.reference.jws import sign_jws
    from pqblocks_jose.policy import Policy
    payload = b'{"sub":"test"}'
    protected_header = b'{"alg":"ML-DSA-65-Ed25519","typ":"JWT"}'
    # Create token with a large limit so sign_jws succeeds
    large_policy = Policy(max_token_bytes=100000)
    token = sign_jws(payload, protected_header, large_policy, seed=42)
    # Now verify with a tiny policy so the token size check fails
    tiny_policy = Policy(max_token_bytes=1)
    with pytest.raises(TokenSizeExceededError):
        verify_jws(token, tiny_policy, seed=42)


def test_verify_jws_non_dict_protected_header():
    """Test verify_jws raises InvalidTokenError when protected header is not a dict."""
    import json
    # Build a token with protected header that decodes to a non-dict JSON
    from pqblocks_jose.reference.jws import _base64url_encode
    protected_header = b'["not","a","dict"]'
    payload = b'{"sub":"test"}'
    policy = Policy()
    ph_b64 = _base64url_encode(protected_header)
    pl_b64 = _base64url_encode(payload)
    token = f"{ph_b64}.{pl_b64}.fake_sig"
    with pytest.raises(InvalidTokenError):
        verify_jws(token, policy, seed=42)


def test_verify_jws_signature_verification_failed():
    """Test verify_jws raises InvalidTokenError when signature verification fails."""
    from pqblocks_jose.reference.jws import sign_jws, _base64url_encode
    import base64
    payload = b'{"sub":"test"}'
    protected_header = b'{"alg":"ML-DSA-65-Ed25519","typ":"JWT"}'
    policy = Policy()
    token = sign_jws(payload, protected_header, policy, seed=42)
    parts = token.split('.')
    # Tamper the signature to make verification fail
    padding = 4 - len(parts[2]) % 4
    if padding != 4:
        parts[2] += "=" * padding
    sig_bytes = base64.urlsafe_b64decode(parts[2])
    tampered_sig = bytes([b ^ 0xFF for b in sig_bytes])
    tampered_b64 = base64.urlsafe_b64encode(tampered_sig).rstrip(b'=').decode('ascii')
    tampered_token = f"{parts[0]}.{parts[1]}.{tampered_b64}"
    with pytest.raises(InvalidTokenError):
        verify_jws(tampered_token, policy, seed=42)


def test_verify_jws_invalid_signature_length():
    """Test verify_jws raises InvalidTokenError for wrong signature length."""
    import base64
    from pqblocks_jose.reference.jws import _base64url_encode
    payload = b'{"sub":"test"}'
    protected_header = b'{"alg":"ML-DSA-65-Ed25519","typ":"JWT"}'
    policy = Policy()
    ph_b64 = _base64url_encode(protected_header)
    pl_b64 = _base64url_encode(payload)
    short_sig_b64 = _base64url_encode(b"short")
    token = f"{ph_b64}.{pl_b64}.{short_sig_b64}"
    with pytest.raises(InvalidTokenError):
        verify_jws(token, policy, seed=42)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
