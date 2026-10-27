"""Wycheproof (C2SP) adversarial vectors for pqblocks-jose - run THROUGH the product."""
import vectors_loader
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from pqblocks_jose import pq


def _load_wycheproof_vectors():
    return vectors_loader.load("mldsa_65_verify") + vectors_loader.load("ed25519_test")


def _ed_ok(pk, msg, sig):
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


def test_wycheproof_vectors_load():
    groups = _load_wycheproof_vectors()
    assert len(groups) > 0 and all(g.get("tests") for g in groups)


def test_wycheproof_ed25519_structure():
    """Every Wycheproof Ed25519 case: valid accepted, invalid rejected."""
    n = 0
    for g in vectors_loader.load("ed25519_test"):
        pk = bytes.fromhex(g["publicKey"]["pk"])
        for t in g["tests"]:
            if t["result"] == "acceptable":
                continue
            assert _ed_ok(pk, bytes.fromhex(t["msg"]), bytes.fromhex(t["sig"])) is (t["result"] == "valid"), t["tcId"]
            n += 1
    assert n >= 100


def test_wycheproof_malformed_cases():
    """Every Wycheproof ML-DSA-65 verify case, including malformed ones, gets the right verdict."""
    n = malformed = 0
    for g in vectors_loader.load("mldsa_65_verify"):
        pk = bytes.fromhex(g["publicKey"])
        for t in g["tests"]:
            if t["result"] == "acceptable":
                continue
            ok = pq.mldsa65_verify(pk, bytes.fromhex(t["msg"]), bytes.fromhex(t["sig"]),
                                   bytes.fromhex(t.get("ctx", "")))
            assert ok is (t["result"] == "valid"), (t["tcId"], t["comment"])
            n += 1
            malformed += t["result"] == "invalid"
    assert n >= 100 and malformed >= 10
