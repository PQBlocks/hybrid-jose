"""Tests for S5.1: Key Store: PEM/JWK Loading Helpers."""

import os
import sys
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pqblocks_jose.keypair import generate_keypair, JWS_ALG, JWE_ALG
from pqblocks_jose.keystore import (
    export_to_pem,
    load_private_key_from_pem,
    load_public_key_from_pem,
    export_to_jwk,
    load_jwk_from_file,
)

def test_pem_export_and_load_private():
    """Test PEM private key export and import round-trip."""
    kp = generate_keypair(JWS_ALG, seed=42)
    pem_bytes = export_to_pem(kp)
    assert b"BEGIN PQBLOCKS HYBRID PRIVATE KEY" in pem_bytes
    loaded = load_private_key_from_pem(pem_bytes)
    assert loaded.algorithm == kp.algorithm
    assert loaded.public_key == kp.public_key

def test_pem_load_public():
    """Test PEM public key loading."""
    kp = generate_keypair(JWS_ALG, seed=42)
    pem_bytes = export_to_pem(kp)
    loaded = load_public_key_from_pem(pem_bytes)
    assert loaded.algorithm == kp.algorithm
    assert loaded.public_key == kp.public_key

def test_jwk_export_and_file_load(tmp_path):
    """Test JWK export and load_jwk_from_file round-trip."""
    kp = generate_keypair(JWE_ALG, seed=42)
    jwk_dict = export_to_jwk(kp)
    assert "kty" in jwk_dict
    assert jwk_dict.get("alg") == JWE_ALG

    file_path = str(tmp_path / "key.jwk")
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(jwk_dict, f)

    loaded = load_jwk_from_file(file_path)
    assert loaded.algorithm == kp.algorithm
    assert loaded.public_key == kp.public_key


# === Extended error-path coverage (Check 3 (correctness) repair: keystore 59% -> >=90%) ===
import base64 as _b64

from pqblocks_jose import keystore as _ks
from pqblocks_jose.keypair import KeyPair as _KeyPair
from pqblocks_jose.exceptions import KeyFormatError as _KeyFormatError


def _write_jwk(tmp_path, payload, name="k.jwk"):
    p = str(tmp_path / name)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(payload)
    return p


def test_jwe_pem_private_roundtrip():
    kp = generate_keypair(JWE_ALG, seed=42)
    pem = export_to_pem(kp)
    assert b"BEGIN PQBLOCKS HYBRID PRIVATE KEY" in pem
    loaded = load_private_key_from_pem(pem)
    assert loaded.algorithm == JWE_ALG
    assert loaded.public_key == kp.public_key
    pub = load_public_key_from_pem(pem)
    assert pub.private_key is None
    assert pub.public_key == kp.public_key


def test_jws_public_only_pem_roundtrip():
    kp = generate_keypair(JWS_ALG, seed=42)
    pub_only = _KeyPair(private_key=None, public_key=kp.public_key, algorithm=JWS_ALG)
    pem = export_to_pem(pub_only)
    assert b"BEGIN PQBLOCKS HYBRID PUBLIC KEY" in pem
    loaded = load_public_key_from_pem(pem)
    assert loaded.private_key is None
    assert loaded.public_key == kp.public_key


def test_jwe_public_only_pem_roundtrip():
    kp = generate_keypair(JWE_ALG, seed=42)
    pub_only = _KeyPair(private_key=None, public_key=kp.public_key, algorithm=JWE_ALG)
    pem = export_to_pem(pub_only)
    loaded = load_public_key_from_pem(pem)
    assert loaded.private_key is None
    assert loaded.public_key == kp.public_key


def test_load_private_pem_non_bytes():
    with pytest.raises(_KeyFormatError):
        load_private_key_from_pem("not bytes")


def test_decode_pem_missing_algorithm():
    raw = _ks._b64url_encode(b"x" * 16)
    pem = (f"-----BEGIN PQBLOCKS HYBRID PRIVATE KEY-----\n{raw}\n"
           f"-----END PQBLOCKS HYBRID PRIVATE KEY-----\n").encode()
    with pytest.raises(_KeyFormatError):
        load_private_key_from_pem(pem)


def test_decode_pem_missing_material():
    pem = (b"-----BEGIN PQBLOCKS HYBRID PRIVATE KEY-----\n"
           b"Algorithm: ML-DSA-65-Ed25519\n"
           b"-----END PQBLOCKS HYBRID PRIVATE KEY-----\n")
    with pytest.raises(_KeyFormatError):
        load_private_key_from_pem(pem)


def test_decode_pem_bad_base64():
    pem = (b"-----BEGIN PQBLOCKS HYBRID PRIVATE KEY-----\n"
           b"Algorithm: ML-DSA-65-Ed25519\n"
           b"!!!not-base64!!!\n"
           b"-----END PQBLOCKS HYBRID PRIVATE KEY-----\n")
    with pytest.raises(_KeyFormatError):
        load_private_key_from_pem(pem)


def test_load_private_jws_bad_length():
    pem = _ks._encode_pem("private", JWS_ALG, _ks._b64url_encode(b"short"))
    with pytest.raises(_KeyFormatError):
        load_private_key_from_pem(pem)


def test_load_private_jwe_bad_length():
    pem = _ks._encode_pem("private", JWE_ALG, _ks._b64url_encode(b"short"))
    with pytest.raises(_KeyFormatError):
        load_private_key_from_pem(pem)


def test_load_private_unsupported_alg():
    pem = _ks._encode_pem("private", "UNKNOWN-ALG", _ks._b64url_encode(b"x" * 32))
    with pytest.raises(_KeyFormatError):
        load_private_key_from_pem(pem)


def test_load_public_non_bytes():
    with pytest.raises(_KeyFormatError):
        load_public_key_from_pem(12345)


def test_load_public_jws_bad_length():
    pem = _ks._encode_pem("public", JWS_ALG, _ks._b64url_encode(b"short"))
    with pytest.raises(_KeyFormatError):
        load_public_key_from_pem(pem)


def test_load_public_jwe_bad_length():
    pem = _ks._encode_pem("public", JWE_ALG, _ks._b64url_encode(b"short"))
    with pytest.raises(_KeyFormatError):
        load_public_key_from_pem(pem)


def test_load_public_unsupported_alg():
    pem = _ks._encode_pem("public", "UNKNOWN-ALG", _ks._b64url_encode(b"x" * 32))
    with pytest.raises(_KeyFormatError):
        load_public_key_from_pem(pem)


def test_load_jwk_non_str_path():
    with pytest.raises(_KeyFormatError):
        load_jwk_from_file(123)


def test_load_jwk_missing_file(tmp_path):
    with pytest.raises(_KeyFormatError):
        load_jwk_from_file(str(tmp_path / "nope.jwk"))


def test_load_jwk_bad_json(tmp_path):
    with pytest.raises(_KeyFormatError):
        load_jwk_from_file(_write_jwk(tmp_path, "{not json"))


def test_load_jwk_non_dict(tmp_path):
    with pytest.raises(_KeyFormatError):
        load_jwk_from_file(_write_jwk(tmp_path, "[1,2,3]"))


def test_load_jwk_missing_kty(tmp_path):
    with pytest.raises(_KeyFormatError):
        load_jwk_from_file(_write_jwk(tmp_path, json.dumps({"alg": JWS_ALG})))


def test_load_jwk_missing_alg(tmp_path):
    with pytest.raises(_KeyFormatError):
        load_jwk_from_file(_write_jwk(tmp_path, json.dumps({"kty": "JOSE-Hybrid"})))


def test_load_jwk_missing_n(tmp_path):
    with pytest.raises(_KeyFormatError):
        load_jwk_from_file(_write_jwk(
            tmp_path, json.dumps({"kty": "JOSE-Hybrid", "alg": JWS_ALG})))


def test_load_jwk_bad_n(tmp_path):
    with pytest.raises(_KeyFormatError):
        load_jwk_from_file(_write_jwk(tmp_path, json.dumps(
            {"kty": "JOSE-Hybrid", "alg": JWS_ALG, "n": "!!!"})))


def test_jwk_jws_private_roundtrip(tmp_path):
    kp = generate_keypair(JWS_ALG, seed=42)
    d = export_to_jwk(kp)
    assert d["alg"] == JWS_ALG and "d" in d
    loaded = load_jwk_from_file(_write_jwk(tmp_path, json.dumps(d)))
    assert loaded.public_key == kp.public_key
    assert loaded.private_key == kp.private_key


def test_jwk_jws_public_only(tmp_path):
    kp = generate_keypair(JWS_ALG, seed=42)
    pub_only = _KeyPair(private_key=None, public_key=kp.public_key, algorithm=JWS_ALG)
    d = export_to_jwk(pub_only)
    assert "d" not in d
    loaded = load_jwk_from_file(_write_jwk(tmp_path, json.dumps(d), "pub.jwk"))
    assert loaded.private_key is None
    assert loaded.public_key == kp.public_key


def test_jwk_jws_pub_bad_length(tmp_path):
    with pytest.raises(_KeyFormatError):
        load_jwk_from_file(_write_jwk(tmp_path, json.dumps(
            {"kty": "JOSE-Hybrid", "alg": JWS_ALG,
             "n": _ks._b64url_encode(b"short")})))
def test_jwk_jws_priv_bad_b64(tmp_path):
    kp = generate_keypair(JWS_ALG, seed=42)
    with pytest.raises(_KeyFormatError):
        load_jwk_from_file(_write_jwk(tmp_path, json.dumps(
            {"kty": "JOSE-Hybrid", "alg": JWS_ALG,
             "n": _ks._b64url_encode(kp.public_key), "d": "!!!"})))


def test_jwk_jws_priv_bad_length(tmp_path):
    kp = generate_keypair(JWS_ALG, seed=42)
    with pytest.raises(_KeyFormatError):
        load_jwk_from_file(_write_jwk(tmp_path, json.dumps(
            {"kty": "JOSE-Hybrid", "alg": JWS_ALG,
             "n": _ks._b64url_encode(kp.public_key),
             "d": _ks._b64url_encode(b"short")})))
def test_jwk_jwe_priv_bad_length(tmp_path):
    kp = generate_keypair(JWE_ALG, seed=42)
    with pytest.raises(_KeyFormatError):
        load_jwk_from_file(_write_jwk(tmp_path, json.dumps(
            {"kty": "JOSE-Hybrid", "alg": JWE_ALG,
             "n": _ks._b64url_encode(kp.public_key),
             "d": _ks._b64url_encode(b"short")})))
def test_jwk_jwe_pub_bad_length(tmp_path):
    with pytest.raises(_KeyFormatError):
        load_jwk_from_file(_write_jwk(tmp_path, json.dumps(
            {"kty": "JOSE-Hybrid", "alg": JWE_ALG,
             "n": _ks._b64url_encode(b"short")})))
def test_jwk_unsupported_alg(tmp_path):
    with pytest.raises(_KeyFormatError):
        load_jwk_from_file(_write_jwk(tmp_path, json.dumps(
            {"kty": "JOSE-Hybrid", "alg": "UNKNOWN-ALG",
             "n": _ks._b64url_encode(b"x" * 32)})))


def test_export_pem_non_keypair():
    with pytest.raises(TypeError):
        export_to_pem("not a keypair")


def test_export_pem_bad_alg():
    with pytest.raises(ValueError):
        export_to_pem(_KeyPair(private_key=b"x", public_key=b"y", algorithm="NOPE"))


def test_export_jwk_non_keypair():
    with pytest.raises(TypeError):
        export_to_jwk("not a keypair")


def test_export_jwk_bad_alg():
    with pytest.raises(ValueError):
        export_to_jwk(_KeyPair(private_key=None, public_key=b"y", algorithm="NOPE"))


def test_b64url_helpers_roundtrip():
    assert _ks._b64url_decode(_ks._b64url_encode(b"\x00\xff hello")) == b"\x00\xff hello"


def test_generate_keypair_bad_alg_type():
    from pqblocks_jose.keypair import generate_keypair as _gen
    with pytest.raises(TypeError):
        _gen(123)


def test_generate_keypair_bad_seed():
    from pqblocks_jose.keypair import generate_keypair as _gen
    with pytest.raises(ValueError):
        _gen(JWS_ALG, seed="42")


def test_generate_keypair_unknown_alg():
    from pqblocks_jose.keypair import generate_keypair as _gen
    from pqblocks_jose.keypair import UnknownAlgorithmError
    with pytest.raises(UnknownAlgorithmError):
        # pass a seed so this isolates algorithm validation rather than tripping
        # the credential guard first
        _gen("UNKNOWN", seed=42)
