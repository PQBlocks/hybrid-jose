"""NIST ACVP KAT vectors for pqblocks-jose - run THROUGH the product."""
import vectors_loader
import pytest

from pqblocks_jose import pq


def _load_kat_vectors():
    return [g for g in vectors_loader.load("ML-DSA-sigVer-FIPS204") if not g["_source"].endswith("-tr1")]


def test_acvp_vectors_load():
    groups = _load_kat_vectors()
    assert len(groups) > 0, "No ACVP KAT vector groups found"
    assert all("tests" in g and g["tests"] for g in groups)


def test_acvp_ml_dsa_signatures():
    """Every pure, external ML-DSA-65 sigVer case gives NIST's expected verdict."""
    cases = [t for g in _load_kat_vectors() if g.get("parameterSet") == "ML-DSA-65"
             and g.get("preHash") == "pure" and g.get("signatureInterface") == "external" for t in g["tests"]]
    assert len(cases) >= 10
    for t in cases:
        got = pq.mldsa65_verify(bytes.fromhex(t["pk"]), bytes.fromhex(t["message"]),
                                bytes.fromhex(t["signature"]), bytes.fromhex(t.get("context", "")))
        assert got is bool(t["testPassed"]), (t["tcId"], t.get("reason"))


def test_acvp_field_counts():
    for g in _load_kat_vectors():
        for t in g["tests"]:
            assert len(t) >= 2, f"KAT test entry has only {len(t)} field(s): {list(t.keys())}"
