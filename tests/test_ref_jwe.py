"""Tests for Reference JWE: HPKE-X-Wing -> A256GCM (spec section 1.3, feature S3).

Covers the worked example plus edge cases EC1, EC5, EC6, EC7, EC9, EC10.
"""

import base64
import json

import pytest

from pqblocks_jose.exceptions import (
    DecryptionError,
    InvalidTokenError,
    PolicyMismatchError,
    TokenSizeExceededError,
)
from pqblocks_jose.policy import Policy
from pqblocks_jose.reference.jwe import decrypt_jwe, encrypt_jwe


def _b64u_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def test_worked_example():
    """Basic JWE round trip with byte-level structural checks (spec section 1.3)."""
    plaintext = b'{"sub":"test","iat":1700000000}'
    protected_header = b'{"alg":"HPKE-X25519MLKEM768","enc":"A256GCM","typ":"JWT"}'
    policy = Policy()

    token = encrypt_jwe(plaintext, protected_header, policy, seed=42)
    parts = token.split(".")
    assert len(parts) == 5
    assert len(_b64u_decode(parts[1])) == 1120
    assert len(_b64u_decode(parts[2])) == 12
    assert len(_b64u_decode(parts[4])) == 16

    result = decrypt_jwe(token, policy, seed=42)
    assert result.plaintext == plaintext
    assert result.algorithm == "HPKE-X25519MLKEM768"
    assert result.enc == "A256GCM"
    assert json.loads(result.protected_header) == {
        "alg": "HPKE-X25519MLKEM768",
        "enc": "A256GCM",
        "typ": "JWT",
    }


def test_empty_plaintext():
    """EC1: empty plaintext round-trips."""
    plaintext = b""
    protected_header = b'{"alg":"HPKE-X25519MLKEM768","enc":"A256GCM","typ":"JWT"}'
    policy = Policy()

    token = encrypt_jwe(plaintext, protected_header, policy, seed=7)
    result = decrypt_jwe(token, policy, seed=7)
    assert result.plaintext == plaintext
    assert result.algorithm == "HPKE-X25519MLKEM768"


def test_hkdf_large_ikm():
    """EC5: HKDF-SHA256 handles large inputs; 1MB ikm derives 32 bytes."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    ikm = b"k" * (1024 * 1024)
    cek = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",
        info=b"JOSE_PostQuantum_Traditional_Hybrid X25519MLKEM768",
    ).derive(ikm)
    assert len(cek) == 32

    plaintext = b'{"data":"' + b"x" * 1000 + b'"}'
    protected_header = b'{"alg":"HPKE-X25519MLKEM768","enc":"A256GCM","typ":"JWT"}'
    policy = Policy()
    token = encrypt_jwe(plaintext, protected_header, policy, seed=11)
    result = decrypt_jwe(token, policy, seed=11)
    assert result.plaintext == plaintext


def test_rng_independence():
    """EC6: same seed is bit-identical; different seeds differ; both decrypt."""
    plaintext = b'{"sub":"test"}'
    protected_header = b'{"alg":"HPKE-X25519MLKEM768","enc":"A256GCM","typ":"JWT"}'
    policy = Policy()

    # Note: hedged signing behavior updated
    # That was the bug, not a property: a seed-derived ephemeral key and AES-GCM nonce
    # repeat key+nonce across messages (NIST SP 800-38D s8 forbids it) and FIPS 203 7.2
    # requires fresh Encaps randomness. Same seed -> same RECIPIENT key; every token
    # differs and each decrypts with that key.
    token_a1 = encrypt_jwe(plaintext, protected_header, policy, seed=42)
    token_a2 = encrypt_jwe(plaintext, protected_header, policy, seed=42)
    assert token_a1 != token_a2
    assert decrypt_jwe(token_a2, policy, seed=42).plaintext == plaintext

    token_b = encrypt_jwe(plaintext, protected_header, policy, seed=43)
    assert token_a1 != token_b

    assert decrypt_jwe(token_a1, policy, seed=42).plaintext == plaintext
    assert decrypt_jwe(token_b, policy, seed=43).plaintext == plaintext


def test_key_rotation_overlap():
    """EC7: token sealed under v1 verifies under v1 and v2 (current + previous)."""
    plaintext = b'{"sub":"test"}'
    protected_header = b'{"alg":"HPKE-X25519MLKEM768","enc":"A256GCM","typ":"JWT"}'
    policy_v1 = Policy(version=1)
    policy_v2 = Policy(version=2)

    token = encrypt_jwe(plaintext, protected_header, policy_v1, seed=42)
    assert decrypt_jwe(token, policy_v1, seed=42).plaintext == plaintext
    assert decrypt_jwe(token, policy_v2, seed=42).plaintext == plaintext


def test_invalid_ciphertext_rejected():
    """EC9: tampered encapsulated key fails loudly with DecryptionError."""
    plaintext = b'{"sub":"test"}'
    protected_header = b'{"alg":"HPKE-X25519MLKEM768","enc":"A256GCM","typ":"JWT"}'
    policy = Policy()

    token = encrypt_jwe(plaintext, protected_header, policy, seed=42)
    parts = token.split(".")
    assert len(parts) == 5

    encrypted_key = bytearray(_b64u_decode(parts[1]))
    assert len(encrypted_key) == 1120
    encrypted_key[5] ^= 0xFF
    encrypted_key[10] ^= 0xFF
    corrupted_b64 = base64.urlsafe_b64encode(bytes(encrypted_key)).rstrip(b"=").decode(
        "ascii"
    )
    corrupted = f"{parts[0]}.{corrupted_b64}.{parts[2]}.{parts[3]}.{parts[4]}"
    with pytest.raises(DecryptionError):
        decrypt_jwe(corrupted, policy, seed=42)


def test_policy_mismatch_rejected():
    """EC10: non-canonical KDF policy is rejected with PolicyMismatchError."""
    plaintext = b'{"sub":"test"}'
    protected_header = b'{"alg":"HPKE-X25519MLKEM768","enc":"A256GCM","typ":"JWT"}'
    policy_bad = Policy(kdf_info="Wrong_KDF_Info")

    with pytest.raises(PolicyMismatchError):
        encrypt_jwe(plaintext, protected_header, policy_bad, seed=42)

    policy_ok = Policy()
    token = encrypt_jwe(plaintext, protected_header, policy_ok, seed=42)
    with pytest.raises(PolicyMismatchError):
        decrypt_jwe(token, policy_bad, seed=42)


def test_invalid_token_length():
    """Malformed compact serializations are rejected with InvalidTokenError."""
    policy = Policy()
    with pytest.raises(InvalidTokenError):
        decrypt_jwe("only.two", policy, seed=42)
    with pytest.raises(InvalidTokenError):
        decrypt_jwe("a.b.c.d", policy, seed=42)

    token = encrypt_jwe(
        b'{"sub":"test"}',
        b'{"alg":"HPKE-X25519MLKEM768","enc":"A256GCM","typ":"JWT"}',
        policy,
        seed=42,
    )
    with pytest.raises(InvalidTokenError):
        decrypt_jwe(token[:-10], policy, seed=42)


def test_wrong_alg_header():
    """Tokens with wrong alg/enc are rejected with InvalidTokenError."""
    plaintext = b'{"sub":"test"}'
    protected_header = b'{"alg":"HPKE-X25519MLKEM768","enc":"A256GCM","typ":"JWT"}'
    policy = Policy()
    token = encrypt_jwe(plaintext, protected_header, policy, seed=42)
    parts = token.split(".")
    assert len(parts) == 5

    header = json.loads(_b64u_decode(parts[0]).decode("utf-8"))
    header["alg"] = "wrong-alg"
    bad_header = base64.urlsafe_b64encode(
        json.dumps(header).encode("utf-8")
    ).rstrip(b"=").decode("ascii")
    with pytest.raises(InvalidTokenError):
        decrypt_jwe(
            f"{bad_header}.{parts[1]}.{parts[2]}.{parts[3]}.{parts[4]}",
            policy,
            seed=42,
        )


def test_token_size_cap_enforced():
    """EC8 analogue: oversize tokens raise TokenSizeExceededError with sizes."""
    large_plaintext = b'{"data":"' + b"x" * 2000 + b'"}'
    protected_header = b'{"alg":"HPKE-X25519MLKEM768","enc":"A256GCM","typ":"JWT"}'
    policy = Policy(max_token_bytes=100)

    with pytest.raises(TokenSizeExceededError) as exc:
        encrypt_jwe(large_plaintext, protected_header, policy, seed=42)
    assert exc.value.actual > exc.value.limit


# === Error Path Tests for Decoration Coverage ===

def test_decrypt_token_not_string_raises():
    """Decrypt with non-string token must raise InvalidTokenError."""
    policy = Policy()
    with pytest.raises(InvalidTokenError):
        decrypt_jwe(b"not a string", policy, seed=42)


def test_decrypt_invalid_encrypted_key_length():
    token = encrypt_jwe(b'{"sub":"test"}', b'{"alg":"HPKE-X25519MLKEM768","enc":"A256GCM"}', Policy(), seed=42)
    parts = token.split(".")
    bad_encrypted_key = base64.urlsafe_b64encode(b"short" + b"x" * 1000).rstrip(b"=").decode("ascii")
    bad_token = f"{parts[0]}.{bad_encrypted_key}.{parts[2]}.{parts[3]}.{parts[4]}"
    with pytest.raises(DecryptionError):
        decrypt_jwe(bad_token, Policy(), seed=42)


def test_decrypt_invalid_x25519_ephemeral_key():
    token = encrypt_jwe(b'{"sub":"test"}', b'{"alg":"HPKE-X25519MLKEM768","enc":"A256GCM"}', Policy(), seed=42)
    parts = token.split(".")
    bad_ct = base64.urlsafe_b64encode(b"\xff" * 20 + b"y" * 1092).rstrip(b"=").decode("ascii")
    bad_token = f"{parts[0]}.{parts[1]}.{parts[2]}.{bad_ct}.{parts[4]}"
    with pytest.raises(DecryptionError):
        decrypt_jwe(bad_token, Policy(), seed=42)


def test_decrypt_tampered_ciphertext():
    token = encrypt_jwe(b'{"sub":"test"}', b'{"alg":"HPKE-X25519MLKEM768","enc":"A256GCM"}', Policy(), seed=42)
    parts = token.split(".")
    ciphertext = bytearray(_b64u_decode(parts[3]))
    ciphertext[0] ^= 0xFF
    bad_ciphertext = base64.urlsafe_b64encode(bytes(ciphertext)).rstrip(b"=").decode("ascii")
    bad_token = f"{parts[0]}.{parts[1]}.{parts[2]}.{bad_ciphertext}.{parts[4]}"
    with pytest.raises(DecryptionError):
        decrypt_jwe(bad_token, Policy(), seed=42)


def test_encrypt_invalid_plaintext_type():
    policy = Policy()
    with pytest.raises(InvalidTokenError):
        encrypt_jwe("not bytes", b'{"alg":"HPKE-X25519MLKEM768","enc":"A256GCM"}', policy, seed=42)


def test_encrypt_invalid_header_type():
    policy = Policy()
    with pytest.raises(InvalidTokenError):
        encrypt_jwe(b"plaintext", "not bytes", policy, seed=42)


def test_decrypt_unsupported_algorithm():
    protected_header = b'{"alg":"unsupported-alg","enc":"A256GCM"}'
    policy = Policy()
    token = "eyJhbGciOiJ1c3VuY291bnRlZCIsImVuYyI6IkEyNTZHQ00ifQ.a.a.a.a.a"
    with pytest.raises(InvalidTokenError):
        decrypt_jwe(token, policy, seed=42)


# === Extended error-path coverage (Check 3 (correctness) repair: reference/jwe 82% -> >=90%) ===
from pqblocks_jose.reference.jwe import (
    JsonStr as _JsonStr,
    _base64url_decode as _ref_b64dec,
)


def test_jsonstr_getitem_dict_access():
    s = _JsonStr('{"a": 1, "b": "x"}')
    assert s["a"] == 1
    assert s.get("b") == "x"
    assert s.get("missing", "dflt") == "dflt"


def test_jsonstr_getitem_fallback():
    s = _JsonStr("abc")
    assert s[0] == "a"
    assert s.get("k", "d") == "d"


def test_policy_kdf_mismatch_rejected_ref():
    with pytest.raises(PolicyMismatchError):
        encrypt_jwe(b"pt", b'{"alg":"HPKE-X25519MLKEM768","enc":"A256GCM"}',
                    Policy(kdf="SHA3-256"), seed=42)


def test_policy_version_mismatch_rejected_ref():
    with pytest.raises(PolicyMismatchError):
        encrypt_jwe(b"pt", b'{"alg":"HPKE-X25519MLKEM768","enc":"A256GCM"}',
                    Policy(version=99), seed=42)


def test_ref_b64_decode_non_str():
    with pytest.raises(InvalidTokenError):
        _ref_b64dec(b"not-a-str")


def test_ref_b64_decode_bad():
    with pytest.raises(InvalidTokenError):
        _ref_b64dec("!!!abc")


def test_encrypt_malformed_header():
    with pytest.raises(InvalidTokenError):
        encrypt_jwe(b"pt", b"not json", Policy(), seed=42)


def test_encrypt_non_dict_header():
    with pytest.raises(InvalidTokenError):
        encrypt_jwe(b"pt", b"123", Policy(), seed=42)


def test_decrypt_bad_base64_part():
    with pytest.raises(InvalidTokenError):
        decrypt_jwe("!!!.!!!.!!!.!!!.!!!", Policy(), seed=42)


def test_decrypt_size_cap():
    token = encrypt_jwe(b'{"sub":"t"}',
                        b'{"alg":"HPKE-X25519MLKEM768","enc":"A256GCM"}',
                        Policy(), seed=42)
    with pytest.raises(TokenSizeExceededError):
        decrypt_jwe(token, Policy(max_token_bytes=10), seed=42)


def test_decrypt_bad_nonce_length():
    token = encrypt_jwe(b'{"sub":"t"}',
                        b'{"alg":"HPKE-X25519MLKEM768","enc":"A256GCM"}',
                        Policy(), seed=42)
    parts = token.split(".")
    bad_iv = base64.urlsafe_b64encode(b"short").rstrip(b"=").decode("ascii")
    with pytest.raises(InvalidTokenError):
        decrypt_jwe(f"{parts[0]}.{parts[1]}.{bad_iv}.{parts[3]}.{parts[4]}",
                    Policy(), seed=42)


def test_decrypt_bad_tag_length():
    token = encrypt_jwe(b'{"sub":"t"}',
                        b'{"alg":"HPKE-X25519MLKEM768","enc":"A256GCM"}',
                        Policy(), seed=42)
    parts = token.split(".")
    bad_tag = base64.urlsafe_b64encode(b"short").rstrip(b"=").decode("ascii")
    with pytest.raises(InvalidTokenError):
        decrypt_jwe(f"{parts[0]}.{parts[1]}.{parts[2]}.{parts[3]}.{bad_tag}",
                    Policy(), seed=42)


def test_decrypt_unsupported_enc():
    token = encrypt_jwe(b'{"sub":"t"}',
                        b'{"alg":"HPKE-X25519MLKEM768","enc":"A256GCM"}',
                        Policy(), seed=42)
    parts = token.split(".")
    hdr = {"alg": "HPKE-X25519MLKEM768", "enc": "A128GCM"}
    bad_h = base64.urlsafe_b64encode(json.dumps(hdr).encode()).rstrip(b"=").decode()
    with pytest.raises(InvalidTokenError):
        decrypt_jwe(f"{bad_h}.{parts[1]}.{parts[2]}.{parts[3]}.{parts[4]}",
                    Policy(), seed=42)


def test_decrypt_non_dict_header():
    hdr = base64.urlsafe_b64encode(b"123").rstrip(b"=").decode("ascii")
    with pytest.raises(InvalidTokenError):
        decrypt_jwe(f"{hdr}.a.a.a.a", Policy(), seed=42)


def test_decrypt_header_bad_json():
    hdr = base64.urlsafe_b64encode(b"not-json").rstrip(b"=").decode("ascii")
    with pytest.raises(InvalidTokenError):
        decrypt_jwe(f"{hdr}.a.a.a.a", Policy(), seed=42)


def test_decrypt_kem_pq_half_tamper():
    token = encrypt_jwe(b'{"sub":"t"}',
                        b'{"alg":"HPKE-X25519MLKEM768","enc":"A256GCM"}',
                        Policy(), seed=42)
    parts = token.split(".")
    ek = bytearray(_b64u_decode(parts[1]))
    assert len(ek) == 1120
    ek[100] ^= 0xFF
    bad_ek = base64.urlsafe_b64encode(bytes(ek)).rstrip(b"=").decode("ascii")
    with pytest.raises(DecryptionError):
        decrypt_jwe(f"{parts[0]}.{bad_ek}.{parts[2]}.{parts[3]}.{parts[4]}",
                    Policy(), seed=42)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
