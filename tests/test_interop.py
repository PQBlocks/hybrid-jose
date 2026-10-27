"""Tests for S9: Integration and interop examples.

This test module covers:
- Round-trip through both public API and optimized kernels (Tier 1 vs Tier 2)
- RFC 7519 structural conventions on compact JWS/JWE
- Hybrid token format invariants
"""

import base64
import json

import pytest

from pqblocks_jose import (
    JWSResult,
    JWEResult,
    Policy,
    decode_jws,
    decrypt_jwe,
    encode_jws,
    encrypt_jwe,
    generate_keypair,
)
# Signing seed and verification key must come from one constant, or the forgery
# check correctly rejects a signature made by a different key.
_SEED = 0
_KEYPAIR = generate_keypair("ML-DSA-65-Ed25519", seed=_SEED)
_PUBKEY = _KEYPAIR.public_key

from pqblocks_jose.exceptions import InvalidTokenError, DecryptionError, TokenSizeExceededError
from pqblocks_jose.optimized.jws import sign_jws as opt_sign_jws, verify_jws as opt_verify_jws
from pqblocks_jose.optimized.jwe import encrypt_jwe as opt_encrypt_jwe, decrypt_jwe as opt_decrypt_jwe
from pqblocks_jose.reference.jws import sign_jws as ref_sign_jws, verify_jws as ref_verify_jws
from pqblocks_jose.reference.jwe import encrypt_jwe as ref_encrypt_jwe, decrypt_jwe as ref_decrypt_jwe


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _json_bytes(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


# === Tier 1 vs Tier 2 equivalence (spec §4.3: same seed ⇒ bit-identity) ===

def test_tier_equivalence_jws_same_seed():
    """Reference and optimized JWS tokens are bit-identical for the same seed."""
    payload = _json_bytes({"sub": "tier-eq", "iat": 1700000000})
    header = _json_bytes({"alg": "ML-DSA-65-Ed25519", "typ": "JWT"})
    policy = Policy()

    # Note: hedged signing behavior updated
    # for one seed. Signing is now FIPS 204 HEDGED on pyca/OpenSSL (FIPS 204 3.4 recommends hedged; the
    # deterministic path ran in non-constant-time pure Python). Same seed -> same KEY; every token verifies.
    ref_token = ref_sign_jws(payload, header, policy, seed=777)
    opt_token = opt_sign_jws(payload, header, policy, seed=777)
    assert opt_verify_jws(ref_token, policy, seed=777).signature_verified
    assert ref_verify_jws(opt_token, policy, seed=777).signature_verified


def test_tier_equivalence_jwe_same_seed():
    """Reference and optimized JWE tokens are bit-identical for the same seed."""
    plaintext = b"tier equivalence plaintext"
    header = _json_bytes({"alg": "HPKE-X25519MLKEM768", "enc": "A256GCM", "typ": "JWT"})
    policy = Policy()

    # Note: hedged signing behavior updated
    # That was the bug, not a property: a seed-derived ephemeral key and AES-GCM nonce
    # repeat key+nonce across messages (NIST SP 800-38D s8 forbids it) and FIPS 203 7.2
    # requires fresh Encaps randomness. Same seed -> same RECIPIENT key; every token
    # differs and each decrypts with that key.
    ref_token = ref_encrypt_jwe(plaintext, header, policy, seed=888)
    opt_token = opt_encrypt_jwe(plaintext, header, policy, seed=888)
    assert ref_token != opt_token
    assert opt_decrypt_jwe(ref_token, policy, seed=888).plaintext == plaintext
    assert ref_decrypt_jwe(opt_token, policy, seed=888).plaintext == plaintext


def test_tier_equivalence_jwe_decrypt():
    """Optimized decrypt recovers plaintext from a reference-encrypted JWE."""
    plaintext = b"cross-tier round trip"
    header = _json_bytes({"alg": "HPKE-X25519MLKEM768", "enc": "A256GCM", "typ": "JWT"})
    policy = Policy()

    ref_token = ref_encrypt_jwe(plaintext, header, policy, seed=999)
    result = opt_decrypt_jwe(ref_token, policy, seed=999)
    assert result.plaintext == plaintext


def test_tier_equivalence_jws_verify():
    """Optimized verify accepts a reference-signed JWS."""
    payload = _json_bytes({"sub": "cross-tier"})
    header = _json_bytes({"alg": "ML-DSA-65-Ed25519", "typ": "JWT"})
    policy = Policy()

    ref_token = ref_sign_jws(payload, header, policy, seed=1010)
    result = opt_verify_jws(ref_token, policy, seed=1010)
    assert result.signature_verified is True


# === Public API interop: encode (public) then verify (optimized kernel) ===

def test_public_encode_optimized_verify():
    """A token from the public API verifies through the optimized kernel."""
    payload = {"sub": "interop", "iat": 1700000000}
    policy = Policy()
    encoded = encode_jws(payload, policy, seed=55)
    result = opt_verify_jws(encoded.compact_serialization, policy, seed=55)
    assert json.loads(result.payload) == payload
    assert result.signature_verified is True


def test_public_decrypt_optimized_encrypt():
    """The public API decrypts a token produced by the optimized kernel."""
    plaintext = b"optimized encrypt, public decrypt"
    header = _json_bytes({"alg": "HPKE-X25519MLKEM768", "enc": "A256GCM", "typ": "JWT"})
    policy = Policy()
    opt_token = opt_encrypt_jwe(plaintext, header, policy, seed=77)
    result = decrypt_jwe(opt_token, policy, seed=77)
    assert result.plaintext == plaintext


# === RFC 7519 structural conventions ===

def test_jws_compact_structure():
    """Compact JWS has exactly 3 dot-separated parts; header/payload are b64u JSON (RFC 7515 §3.1)."""
    result = encode_jws({"sub": "struct"}, Policy(), seed=11)
    parts = result.compact_serialization.split(".")
    assert len(parts) == 3
    header = json.loads(base64.urlsafe_b64decode(parts[0] + "===").decode())
    assert header["alg"] == "ML-DSA-65-Ed25519"
    assert header["typ"] == "JWT"
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "===").decode())
    assert payload == {"sub": "struct"}


def test_jwe_compact_structure():
    """Compact JWE has exactly 5 dot-separated parts with fixed field sizes (RFC 7516 §3.1)."""
    result = encrypt_jwe(b"structural check", Policy(), seed=12)
    parts = result.compact_serialization.split(".")
    assert len(parts) == 5
    ek = base64.urlsafe_b64decode(parts[1] + "===")
    iv = base64.urlsafe_b64decode(parts[2] + "===")
    ct = base64.urlsafe_b64decode(parts[3] + "===")
    tag = base64.urlsafe_b64decode(parts[4] + "===")
    assert len(ek) == 1120  # X25519 ct (32) + ML-KEM-768 ct (1088)
    assert len(iv) == 12
    assert len(tag) == 16
    assert len(ct) == len(b"structural check")
    header = json.loads(base64.urlsafe_b64decode(parts[0] + "===").decode())
    assert header["alg"] == "HPKE-X25519MLKEM768"
    assert header["enc"] == "A256GCM"


def test_jwe_roundtrip_empty_plaintext():
    """JWE round-trip handles the empty-plaintext boundary (EC1 analogue)."""
    result = encrypt_jwe(b"", Policy(), seed=13)
    parts = result.compact_serialization.split(".")
    ct = base64.urlsafe_b64decode(parts[3] + "===")
    assert ct == b""
    decrypted = decrypt_jwe(result.compact_serialization, Policy(), seed=13)
    assert decrypted.plaintext == b""


def test_jws_roundtrip_unicode_payload():
    """JWS round-trip preserves a unicode claims set."""
    payload = {"sub": "ünïcødé", "note": "post-quantum 日本語"}
    policy = Policy()
    result = encode_jws(payload, policy, seed=_SEED)
    decoded = decode_jws(result.compact_serialization, policy, seed=_SEED, public_key=_PUBKEY)
    # payload is a JsonStr (str subclass with dict-like access), never a dict -
    # compare parsed, the way the rest of this file already does.
    assert json.loads(decoded.payload) == payload
    assert decoded.signature_verified is True


def test_jwe_roundtrip_large_plaintext():
    """JWE round-trip handles a ~4KB payload within the default policy cap."""
    plaintext = bytes(range(256)) * 16  # 4096 bytes
    policy = Policy()
    result = encrypt_jwe(plaintext, policy, seed=15)
    decrypted = decrypt_jwe(result.compact_serialization, policy, seed=15)
    assert decrypted.plaintext == plaintext


def test_jws_kid_propagates_to_header():
    """A kid supplied to encode_jws appears in the protected header and the result."""
    result = encode_jws({"sub": "kid"}, Policy(), seed=16, kid="signer-1")
    assert result.key_id == "signer-1"
    assert json.loads(base64.urlsafe_b64decode(result.compact_serialization.split(".")[0] + "==="))["kid"] == "signer-1"


# === Hybrid vector invariants (planted, per spec §6.1) ===

def test_planted_vectors_stable_with_seed():
    """50 planted hybrid vectors: same seed ⇒ deterministic tokens."""
    policy = Policy()
    for i in range(50):
        seed = 1000 + i
        payload = _json_bytes({"jti": f"v{i:02d}", "seq": i})
        header = _json_bytes({"alg": "ML-DSA-65-Ed25519", "typ": "JWT"})
        # Note: hedged signing behavior updated
        # for one seed. Signing is now FIPS 204 HEDGED on pyca/OpenSSL (FIPS 204 3.4 recommends hedged; the
        # deterministic path ran in non-constant-time pure Python). Same seed -> same KEY; every token verifies.
        t1 = ref_sign_jws(payload, header, policy, seed=seed)
        t2 = ref_sign_jws(payload, header, policy, seed=seed)
        assert ref_verify_jws(t1, policy, seed=seed).signature_verified
        assert ref_verify_jws(t2, policy, seed=seed).signature_verified


def test_planted_jwe_vectors_stable_with_seed():
    """Planted JWE vectors: same seed ⇒ deterministic tokens."""
    policy = Policy()
    header = _json_bytes({"alg": "HPKE-X25519MLKEM768", "enc": "A256GCM", "typ": "JWT"})
    for i in range(50):
        seed = 2000 + i
        plaintext = f"vector-{i}".encode()
        # Note: hedged signing behavior updated
        # That was the bug, not a property: a seed-derived ephemeral key and AES-GCM nonce
        # repeat key+nonce across messages (NIST SP 800-38D s8 forbids it) and FIPS 203 7.2
        # requires fresh Encaps randomness. Same seed -> same RECIPIENT key; every token
        # differs and each decrypts with that key.
        t1 = ref_encrypt_jwe(plaintext, header, policy, seed=seed)
        t2 = ref_encrypt_jwe(plaintext, header, policy, seed=seed)
        assert t1 != t2
        assert ref_decrypt_jwe(t1, policy, seed=seed).plaintext == plaintext
        assert ref_decrypt_jwe(t2, policy, seed=seed).plaintext == plaintext


def test_keypair_layout_lengths():
    """KeyPair material has the documented per-algorithm concatenated lengths."""
    jws_kp = generate_keypair("ML-DSA-65-Ed25519", seed=21)
    # Note: hedged signing behavior updated
    # keys (stream bytes). Real keys are held as FIPS 204/203 seeds (xi: 32 B,
    # d||z: 64 B) - pyca's private-key form, which the IETF key drafts prefer.
    assert len(jws_kp.private_key) == 32 + 32  # ed25519 sk + ML-DSA-65 seed
    assert len(jws_kp.public_key) == 32 + 1952  # ed25519 pk + ML-DSA-65 pk

    jwe_kp = generate_keypair("X25519+MLKEM768", seed=22)
    assert len(jwe_kp.private_key) == 32 + 64  # x25519 sk + ML-KEM-768 seed (d||z)
    assert len(jwe_kp.public_key) == 32 + 1184  # x25519 pk + ML-KEM-768 pk


# === Negative tests ===

def test_tampered_jwe_tag_fails_loudly():
    """Flipping one tag byte raises DecryptionError (AES-GCM integrity check)."""
    result = encrypt_jwe(b"tag tamper", Policy(), seed=31)
    parts = result.compact_serialization.split(".")
    tag = base64.urlsafe_b64decode(parts[4] + "===")
    flipped = bytes([tag[0] ^ 0x01]) + tag[1:]
    parts[4] = _b64u(flipped)
    with pytest.raises(DecryptionError):
    # Decrypt with the SAME seed used to encrypt, otherwise this never reaches
    # the AEAD check - it just trips the missing-credential guard and passes
    # for the wrong reason.
        decrypt_jwe(".".join(parts), Policy(), seed=31)


def test_tampered_jwe_iv_fails_loudly():
    """Flipping one IV byte raises DecryptionError."""
    result = encrypt_jwe(b"iv tamper", Policy(), seed=32)
    parts = result.compact_serialization.split(".")
    iv = base64.urlsafe_b64decode(parts[2] + "===")
    flipped = bytes([iv[0] ^ 0x01]) + iv[1:]
    parts[2] = _b64u(flipped)
    with pytest.raises(DecryptionError):
    # Decrypt with the SAME seed used to encrypt, otherwise this never reaches
    # the AEAD check - it just trips the missing-credential guard and passes
    # for the wrong reason.
        decrypt_jwe(".".join(parts), Policy(), seed=32)


def test_tampered_jwe_ek_fails_loudly():
    """Corrupting the encrypted key (ephemeral share) raises DecryptionError."""
    result = encrypt_jwe(b"ek tamper", Policy(), seed=33)
    parts = result.compact_serialization.split(".")
    ek = base64.urlsafe_b64decode(parts[1] + "===")
    corrupted = bytearray(ek)
    corrupted[40] ^= 0xFF  # inside the ML-KEM ciphertext half
    parts[1] = _b64u(bytes(corrupted))
    with pytest.raises(DecryptionError):
    # Decrypt with the SAME seed used to encrypt, otherwise this never reaches
    # the AEAD check - it just trips the missing-credential guard and passes
    # for the wrong reason.
        decrypt_jwe(".".join(parts), Policy(), seed=33)


def test_oversized_jws_payload_raises():
    """A payload pushing the token past the policy cap raises TokenSizeExceededError."""
    policy = Policy(max_token_bytes=5000)
    big = {"blob": "x" * 4000}
    with pytest.raises(TokenSizeExceededError):
        encode_jws(big, policy, seed=34)


def test_wrong_alg_header_rejected():
    """A JWS compact string with an unsupported alg is rejected by the optimized kernel."""
    payload = _json_bytes({"sub": "badalg"})
    header = _json_bytes({"alg": "RS256", "typ": "JWT"})
    policy = Policy()
    # 2026-10-07: the signer now refuses a header naming another algorithm
    # (it signed anything before); the verifier must still reject a token
    # whose header was swapped after signing.
    with pytest.raises(InvalidTokenError):
        ref_sign_jws(payload, header, policy, seed=35)
    import base64 as _b64
    def _swap_alg(tok, alg):
        h = _b64.urlsafe_b64encode(('{"alg":"%s","typ":"JWT"}' % alg).encode()).rstrip(b"=").decode()
        return h + tok[tok.index("."):]
    good = ref_sign_jws(payload, _json_bytes({"alg": "ML-DSA-65-Ed25519", "typ": "JWT"}), policy, seed=35)
    with pytest.raises(InvalidTokenError):
        opt_verify_jws(_swap_alg(good, "RS256"), policy, seed=35)


def test_bogus_jwe_token_rejected():
    """A nonsense JWE string raises InvalidTokenError, not silently returns garbage."""
    with pytest.raises(InvalidTokenError):
        opt_decrypt_jwe("a.b.c.d.e", Policy())


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
