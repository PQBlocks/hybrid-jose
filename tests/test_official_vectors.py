"""pqblocks-jose post-quantum primitives against the published corpus."""
import vectors_loader
import pytest

from pqblocks_jose import Policy, decrypt_jwe, decode_jws, encode_jws, encrypt_jwe, generate_keypair
from pqblocks_jose import pq
from pqblocks_jose.exceptions import DecryptionError, InvalidTokenError


def _pure_sigver_65():
    return [t for g in vectors_loader.load("ML-DSA-sigVer-FIPS204")
            if g.get("parameterSet") == "ML-DSA-65" and g.get("preHash") == "pure"
            and g.get("signatureInterface") == "external" and not g["_source"].endswith("-tr1")
            for t in g["tests"]]


@pytest.mark.parametrize("t", _pure_sigver_65())
def test_mldsa65_verify_matches_nist(t):
    got = pq.mldsa65_verify(bytes.fromhex(t["pk"]), bytes.fromhex(t["message"]),
                            bytes.fromhex(t["signature"]), bytes.fromhex(t.get("context", "")))
    assert got is bool(t["testPassed"]), t.get("reason")


def _det_siggen_65():
    return [t for g in vectors_loader.load("ML-DSA-sigGen-FIPS204")
            if g.get("parameterSet") == "ML-DSA-65" and g.get("deterministic") and g.get("preHash") == "pure"
            and g.get("signatureInterface") == "external" and not g["_source"].endswith("-tr1")
            for t in g["tests"]]


@pytest.mark.parametrize("t", _det_siggen_65())
def test_mldsa65_deterministic_signing_matches_nist(t):
    dilithium_py = pytest.importorskip("dilithium_py")
    from dilithium_py.ml_dsa import ML_DSA_65
    sig = ML_DSA_65.sign(bytes.fromhex(t["sk"]), bytes.fromhex(t["message"]),
                         ctx=bytes.fromhex(t.get("context", "")), deterministic=True)
    assert sig.hex().upper() == t["signature"].upper()


def test_signer_and_verifier_are_independent_and_agree():
    a = generate_keypair("ML-DSA-65-Ed25519", seed=9)
    sig = pq.mldsa65_sign(a.private_key[32:], b"m")     # dilithium-py
    assert pq.mldsa65_verify(a.public_key[32:], b"m", sig)  # pyca / OpenSSL


def _keygen_768():
    return [t for g in vectors_loader.load("ML-KEM-keyGen-FIPS203") if g.get("parameterSet") == "ML-KEM-768"
            for t in g["tests"]]


@pytest.mark.parametrize("t", _keygen_768())
def test_mlkem768_keygen_matches_nist(t):
    pk, _sk = pq.mlkem768_keypair(bytes.fromhex(t["d"] + t["z"]))
    assert pk.hex().upper() == t["ek"].upper()


def test_corpus_was_used():
    assert len(_pure_sigver_65()) >= 10 and len(_keygen_768()) >= 20


POLICY = Policy(version=1, kem="X25519+MLKEM768", sig="MLDSA65+Ed25519", kdf="HKDF-SHA256",
                max_token_bytes=8192, kdf_info="JOSE_PostQuantum_Traditional_Hybrid X25519MLKEM768",
                sig_alg_std="ML-DSA-65-Ed25519")


def test_jws_signed_by_one_key_does_not_verify_under_another():
    a, b = generate_keypair("ML-DSA-65-Ed25519", seed=1), generate_keypair("ML-DSA-65-Ed25519", seed=2)
    token = encode_jws({"sub": "x"}, POLICY, private_key=a.private_key).compact_serialization
    assert decode_jws(token=token, policy=POLICY, public_key=a.public_key).signature_verified
    with pytest.raises(InvalidTokenError):
        decode_jws(token=token, policy=POLICY, public_key=b.public_key)


def test_jws_pq_signature_cannot_be_forged_without_the_key():
    # the simulated verify accepted H(msg) as a signature: no key involved
    a = generate_keypair("ML-DSA-65-Ed25519", seed=3)
    pk_pq = a.public_key[32:]
    assert not pq.mldsa65_verify(pk_pq, b"msg", __import__("hashlib").shake_256(b"msg").digest(3309), b"")


def test_jwe_cannot_be_decrypted_with_the_public_key():
    r = generate_keypair("X25519+MLKEM768", seed=4)
    token = encrypt_jwe(b"secret", POLICY, public_key=r.public_key).compact_serialization
    with pytest.raises(InvalidTokenError):
        decrypt_jwe(token, POLICY, public_key=r.public_key)
    assert decrypt_jwe(token, POLICY, private_key=r.private_key).plaintext == b"secret"


def test_jwe_wrong_private_key_fails():
    r, other = generate_keypair("X25519+MLKEM768", seed=5), generate_keypair("X25519+MLKEM768", seed=6)
    token = encrypt_jwe(b"secret", POLICY, public_key=r.public_key).compact_serialization
    with pytest.raises(DecryptionError):
        decrypt_jwe(token, POLICY, private_key=other.private_key)


def test_jwe_encryption_is_randomized():
    # a seed-derived ephemeral key and nonce meant two messages to the same
    # recipient reused the AES-GCM key/nonce pair
    r = generate_keypair("X25519+MLKEM768", seed=7)
    t1 = encrypt_jwe(b"same", POLICY, public_key=r.public_key).compact_serialization
    t2 = encrypt_jwe(b"same", POLICY, public_key=r.public_key).compact_serialization
    assert t1 != t2


# --- independent crypto review, 2026-10-07 (pqc-crypto-reviewer) ---

def test_keypair_default_is_cryptographically_random():
    # an int seed through SplitMix64 gave every private key <= 64 bits of entropy
    a, b = generate_keypair("ML-DSA-65-Ed25519"), generate_keypair("ML-DSA-65-Ed25519")
    assert a.private_key != b.private_key and a.public_key != b.public_key
    c, d = generate_keypair("X25519+MLKEM768"), generate_keypair("X25519+MLKEM768")
    assert c.private_key != d.private_key


def test_backend_without_seed_does_not_share_a_public_key():
    # seed=None used to hash the string "None": every instance had the same keys
    from pqblocks_jose.optimized.liboqs_backend import LibOQSBackend
    assert LibOQSBackend().ml_dsa_keygen()[1] != LibOQSBackend().ml_dsa_keygen()[1]
    assert LibOQSBackend().ed25519_keygen()[1] != LibOQSBackend().ed25519_keygen()[1]


def test_signing_is_hedged_on_the_constant_time_implementation():
    # deterministic signing ran in pure-Python dilithium-py (not constant-time)
    a = generate_keypair("ML-DSA-65-Ed25519", seed=11)
    s1, s2 = pq.mldsa65_sign(a.private_key[32:], b"m"), pq.mldsa65_sign(a.private_key[32:], b"m")
    assert s1 != s2
    assert pq.mldsa65_verify(a.public_key[32:], b"m", s1) and pq.mldsa65_verify(a.public_key[32:], b"m", s2)


def test_seed_is_not_truncated_to_64_bits():
    # review CRITICAL: seed & 0xFFFF_FFFF_FFFF_FFFF -> seeds 1 and 1 + 2**64 gave identical keys
    assert generate_keypair("ML-DSA-65-Ed25519", seed=1).private_key != \
        generate_keypair("ML-DSA-65-Ed25519", seed=1 + 2**64).private_key
