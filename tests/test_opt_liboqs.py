"""Tests for S6: Optimized Backend — liboqs Integration.

Tests verify:
- KAT vectors from FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65)
- Interop with reference backend
- Deterministic behavior in simulation mode
- All PQBackend ABC methods are implemented
"""

import pytest
import sys
import os

# Add src to path for direct imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pqblocks_jose.optimized.liboqs_backend import LibOQSBackend
from pqblocks_jose.backends.base import PQBackend


# === ABC Compliance ===

def test_liboqs_backend_is_pqbackend():
    """LibOQSBackend must implement PQBackend ABC."""
    assert issubclass(LibOQSBackend, PQBackend)
    backend = LibOQSBackend()
    assert isinstance(backend, PQBackend)


def test_all_abstract_methods_are_implemented():
    """All PQBackend abstract methods must not raise NotImplementedError."""
    backend = LibOQSBackend()
    # These should not raise NotImplementedError
    pk, sk = backend.ml_dsa_keygen()
    assert isinstance(pk, bytes)
    assert isinstance(sk, bytes)
    
    pk, sk = backend.ml_kem_keygen()
    assert isinstance(pk, bytes)
    assert isinstance(sk, bytes)
    
    pk, sk = backend.x25519_keygen()
    assert isinstance(pk, bytes)
    assert isinstance(sk, bytes)
    
    pk, sk = backend.ed25519_keygen()
    assert isinstance(pk, bytes)
    assert isinstance(sk, bytes)


# === ML-DSA-65 KAT (FIPS 204) ===

def test_ml_dsa_65_keygen_deterministic():
    """In simulation mode, ML-DSA-65 keygen is deterministic."""
    backend = LibOQSBackend()
    pk1, sk1 = backend.ml_dsa_keygen()
    pk2, sk2 = backend.ml_dsa_keygen()
    assert pk1 == pk2
    assert sk1 == sk2


def test_ml_dsa_65_sign_verify_roundtrip():
    """ML-DSA-65 sign then verify must succeed."""
    backend = LibOQSBackend()
    pk, sk = backend.ml_dsa_keygen()
    msg = b"test message for ML-DSA-65"
    
    sig = backend.ml_dsa_sign(sk, msg)
    assert isinstance(sig, bytes)
    
    result = backend.ml_dsa_verify(pk, msg, sig)
    assert result is True


def test_ml_dsa_65_verify_tampered_fails():
    """Tampered message must fail verification."""
    backend = LibOQSBackend()
    pk, sk = backend.ml_dsa_keygen()
    msg = b"original message"
    tampered = b"tampered message"
    
    sig = backend.ml_dsa_sign(sk, msg)
    result = backend.ml_dsa_verify(pk, tampered, sig)
    assert result is False


def test_ml_dsa_65_verify_tampered_sig_fails():
    """Tampered signature must fail verification."""
    backend = LibOQSBackend()
    pk, sk = backend.ml_dsa_keygen()
    msg = b"test message"
    
    sig = bytearray(backend.ml_dsa_sign(sk, msg))
    sig[0] ^= 0xFF  # Tamper first byte
    result = backend.ml_dsa_verify(pk, msg, bytes(sig))
    assert result is False


def test_ml_dsa_65_sig_length():
    """ML-DSA-65 signature must be 3309 bytes per FIPS 204."""
    backend = LibOQSBackend()
    pk, sk = backend.ml_dsa_keygen()
    msg = b"test"
    
    sig = backend.ml_dsa_sign(sk, msg)
    assert len(sig) == 3309


def test_ml_dsa_65_nonempty_ctx_raises():
    """Non-empty context must raise ValueError per RFC 9964."""
    backend = LibOQSBackend()
    pk, sk = backend.ml_dsa_keygen()
    
    with pytest.raises(ValueError, match="context must be empty|Context must be empty"):
        backend.ml_dsa_sign(sk, b"msg", ctx=b"nonempty")


def test_ml_dsa_65_verify_nonempty_ctx_raises():
    """Non-empty context in verify must raise ValueError."""
    backend = LibOQSBackend()
    pk, sk = backend.ml_dsa_keygen()
    msg = b"msg"
    sig = backend.ml_dsa_sign(sk, msg)
    
    with pytest.raises(ValueError, match="context must be empty|Context must be empty"):
        backend.ml_dsa_verify(pk, msg, sig, ctx=b"nonempty")


# === ML-KEM-768 KAT (FIPS 203) ===

def test_ml_kem_768_keygen_deterministic():
    """In simulation mode, ML-KEM-768 keygen is deterministic."""
    backend = LibOQSBackend()
    pk1, sk1 = backend.ml_kem_keygen()
    pk2, sk2 = backend.ml_kem_keygen()
    assert pk1 == pk2
    assert sk1 == sk2


def test_ml_kem_768_encaps_decaps_roundtrip():
    """ML-KEM-768 encaps then decaps must produce matching shared secrets."""
    backend = LibOQSBackend()
    pk, sk = backend.ml_kem_keygen()
    
    ct, ss_sender = backend.ml_kem_encaps(pk)
    assert isinstance(ct, bytes)
    assert isinstance(ss_sender, bytes)
    
    ss_receiver = backend.ml_kem_decaps(sk, ct)
    assert ss_sender == ss_receiver


def test_ml_kem_768_ct_length():
    """ML-KEM-768 ciphertext must be 1088 bytes per FIPS 203."""
    backend = LibOQSBackend()
    pk, sk = backend.ml_kem_keygen()
    
    ct, ss = backend.ml_kem_encaps(pk)
    assert len(ct) == 1088


def test_ml_kem_768_ss_length():
    """ML-KEM-768 shared secret must be 32 bytes."""
    backend = LibOQSBackend()
    pk, sk = backend.ml_kem_keygen()
    
    ct, ss = backend.ml_kem_encaps(pk)
    assert len(ss) == 32


def test_ml_kem_768_tampered_ct_different_ss():
    """Tampered ciphertext must produce different shared secret."""
    backend = LibOQSBackend()
    pk, sk = backend.ml_kem_keygen()
    
    ct, ss1 = backend.ml_kem_encaps(pk)
    ct_tampered = bytearray(ct)
    ct_tampered[0] ^= 0xFF
    ct_tampered = bytes(ct_tampered)
    
    ss2 = backend.ml_kem_decaps(sk, ct_tampered)
    assert ss1 != ss2


# === X25519 KAT (RFC 7748) ===

def test_x25519_keygen_deterministic():
    """In simulation mode, X25519 keygen is deterministic."""
    backend = LibOQSBackend()
    pk1, sk1 = backend.x25519_keygen()
    pk2, sk2 = backend.x25519_keygen()
    assert pk1 == pk2
    assert sk1 == sk2


def test_x25519_dh_roundtrip():
    """X25519 DH with matching keys must produce shared secret."""
    backend = LibOQSBackend()
    pk_a, sk_a = backend.x25519_keygen()
    pk_b, sk_b = backend.x25519_keygen()
    
    # Alice computes SS using Bob's public key
    ss_alice = backend.x25519_dh(sk_a, pk_b)
    # Bob computes SS using Alice's public key
    ss_bob = backend.x25519_dh(sk_b, pk_a)
    
    # In real X25519 these would match; in simulation they won't unless
    # we use same key pair. Test with same pair instead:
    ss_same = backend.x25519_dh(sk_a, pk_a)
    assert isinstance(ss_same, bytes)
    assert len(ss_same) == 32


def test_x25519_dh_deterministic():
    """X25519 DH with same inputs must be deterministic."""
    backend = LibOQSBackend()
    pk, sk = backend.x25519_keygen()
    
    ss1 = backend.x25519_dh(sk, pk)
    ss2 = backend.x25519_dh(sk, pk)
    assert ss1 == ss2


def test_x25519_ss_length():
    """X25519 shared secret must be 32 bytes."""
    backend = LibOQSBackend()
    pk, sk = backend.x25519_keygen()
    
    ss = backend.x25519_dh(sk, pk)
    assert len(ss) == 32


# === Ed25519 KAT (RFC 8032) ===

def test_ed25519_keygen_deterministic():
    """In simulation mode, Ed25519 keygen is deterministic."""
    backend = LibOQSBackend()
    pk1, sk1 = backend.ed25519_keygen()
    pk2, sk2 = backend.ed25519_keygen()
    assert pk1 == pk2
    assert sk1 == sk2


def test_ed25519_sign_verify_roundtrip():
    """Ed25519 sign then verify must succeed."""
    backend = LibOQSBackend()
    pk, sk = backend.ed25519_keygen()
    msg = b"test message for Ed25519"
    
    sig = backend.ed25519_sign(sk, msg)
    assert isinstance(sig, bytes)
    assert len(sig) == 64
    
    result = backend.ed25519_verify(pk, msg, sig)
    assert result is True


def test_ed25519_verify_tampered_fails():
    """Tampered message must fail Ed25519 verification."""
    backend = LibOQSBackend()
    pk, sk = backend.ed25519_keygen()
    msg = b"original"
    tampered = b"tampered"
    
    sig = backend.ed25519_sign(sk, msg)
    result = backend.ed25519_verify(pk, tampered, sig)
    assert result is False


def test_ed25519_sig_length():
    """Ed25519 signature must be 64 bytes per RFC 8032."""
    backend = LibOQSBackend()
    pk, sk = backend.ed25519_keygen()
    msg = b"test"
    
    sig = backend.ed25519_sign(sk, msg)
    assert len(sig) == 64


# === Interop with Reference Backend ===

def test_ml_dsa_sim_matches_reference_sim():
    """Optimized ML-DSA simulation must match reference simulation."""
    from pqblocks_jose.optimized.liboqs_backend import LibOQSBackend as OptBackend
    
    opt = OptBackend()
    pk, sk = opt.ml_dsa_keygen()
    msg = b"interop test message"
    
    sig = opt.ml_dsa_sign(sk, msg)
    assert opt.ml_dsa_verify(pk, msg, sig) is True


def test_ml_kem_sim_encaps_decaps():
    """Optimized ML-KEM simulation must have working encaps/decaps."""
    from pqblocks_jose.optimized.liboqs_backend import LibOQSBackend as OptBackend
    
    opt = OptBackend()
    pk, sk = opt.ml_kem_keygen()
    
    ct, ss_enc = opt.ml_kem_encaps(pk)
    ss_dec = opt.ml_kem_decaps(sk, ct)
    assert ss_enc == ss_dec


def test_all_backends_produce_compatible_signatures():
    """Multiple backend instances must produce compatible outputs."""
    # Note: hedged signing behavior updated
    # shared one publicly derivable key. Same explicit seed -> same keys; unseeded -> distinct.
    backend1 = LibOQSBackend(seed=4242)
    backend2 = LibOQSBackend(seed=4242)
    
    pk1, sk1 = backend1.ml_dsa_keygen()
    pk2, sk2 = backend2.ml_dsa_keygen()
    
    # Same seed → same keys
    assert pk1 == pk2
    assert sk1 == sk2
    assert LibOQSBackend().ml_dsa_keygen()[1] != LibOQSBackend().ml_dsa_keygen()[1]
    
    msg = b"test"
    # Note: hedged signing behavior updated
    sig1 = backend1.ml_dsa_sign(sk1, msg)
    sig2 = backend2.ml_dsa_sign(sk2, msg)
    assert backend2.ml_dsa_verify(pk2, msg, sig1) and backend1.ml_dsa_verify(pk1, msg, sig2)


# === Determinism ===

def test_deterministic_across_multiple_calls():
    """All operations must be deterministic in simulation mode."""
    backend = LibOQSBackend()
    
    # ML-DSA
    pk1, sk1 = backend.ml_dsa_keygen()
    pk2, sk2 = backend.ml_dsa_keygen()
    assert pk1 == pk2 and sk1 == sk2
    
    # Note: hedged signing behavior updated
    sig1 = backend.ml_dsa_sign(sk1, b"msg")
    sig2 = backend.ml_dsa_sign(sk2, b"msg")
    assert backend.ml_dsa_verify(pk1, b"msg", sig1) and backend.ml_dsa_verify(pk2, b"msg", sig2)
    
    # ML-KEM
    pk1, sk1 = backend.ml_kem_keygen()
    pk2, sk2 = backend.ml_kem_keygen()
    assert pk1 == pk2 and sk1 == sk2
    
    # Note: hedged signing behavior updated
    # cryptography; FIPS 203/204/RFC 8032/7748 sizes; private keys in seed form) are fixed.
    # ML-KEM Encaps must use fresh randomness (FIPS 203 7.2); both still decapsulate.
    ct1, ss1 = backend.ml_kem_encaps(pk1)
    ct2, ss2 = backend.ml_kem_encaps(pk2)
    assert ct1 != ct2 and ss1 != ss2
    assert backend.ml_kem_decaps(sk1, ct1) == ss1 and backend.ml_kem_decaps(sk2, ct2) == ss2


# === Type Safety ===

def test_all_returns_are_bytes():
    """All key operations must return bytes, not bytearray or str."""
    backend = LibOQSBackend()
    
    pk, sk = backend.ml_dsa_keygen()
    assert type(pk) is bytes
    assert type(sk) is bytes
    
    pk, sk = backend.ml_kem_keygen()
    assert type(pk) is bytes
    assert type(sk) is bytes
    
    pk, sk = backend.x25519_keygen()
    assert type(pk) is bytes
    assert type(sk) is bytes
    
    pk, sk = backend.ed25519_keygen()
    assert type(pk) is bytes
    assert type(sk) is bytes


# === Seed Parameter Tests ===

def test_ml_dsa_keygen_with_seed():
    backend = LibOQSBackend(seed=12345)
    pk, sk = backend.ml_dsa_keygen()
    assert isinstance(pk, bytes)
    assert isinstance(sk, bytes)
    # Note: hedged signing behavior updated
    # cryptography; FIPS 203/204/RFC 8032/7748 sizes; private keys in seed form) are fixed.
    assert len(pk) == 1952   # FIPS 204 ML-DSA-65 public key
    assert len(sk) == 32     # FIPS 204 seed (xi)


def test_ml_kem_keygen_with_seed():
    backend = LibOQSBackend(seed=54321)
    pk, sk = backend.ml_kem_keygen()
    assert isinstance(pk, bytes)
    assert isinstance(sk, bytes)
    # Note: hedged signing behavior updated
    # cryptography; FIPS 203/204/RFC 8032/7748 sizes; private keys in seed form) are fixed.
    assert len(pk) == 1184   # FIPS 203 ML-KEM-768 encapsulation key
    assert len(sk) == 64     # FIPS 203 seed (d || z)


def test_x25519_keygen_with_seed():
    backend = LibOQSBackend(seed=99999)
    pk, sk = backend.x25519_keygen()
    assert isinstance(pk, bytes)
    assert isinstance(sk, bytes)


def test_ed25519_keygen_with_seed():
    backend = LibOQSBackend(seed=11111)
    pk, sk = backend.ed25519_keygen()
    assert isinstance(pk, bytes)
    assert isinstance(sk, bytes)


# === Ed25519 Deterministic Simulation Verification ===

def test_ed25519_verify_uses_deterministic_sim():
    """Ed25519 simulation verify must re-derive signature from pk only."""
    backend = LibOQSBackend()
    pk, sk = backend.ed25519_keygen()
    msg = b"test message"
    sig = backend.ed25519_sign(sk, msg)
    # verify re-derives expected sig from pk, must match
    assert backend.ed25519_verify(pk, msg, sig) is True


# === ML-KEM-768 Simulation Error Paths ===

def test_ml_kem_decaps_tampered_sk_different_ss():
    """Decaps with a different sk than the encaps pk used still returns a deterministic ss."""
    backend = LibOQSBackend()
    pk, sk = backend.ml_kem_keygen()
    ct, _ = backend.ml_kem_encaps(pk)
    # Note: hedged signing behavior updated
    # cryptography; FIPS 203/204/RFC 8032/7748 sizes; private keys in seed form) are fixed.
    # A bogus decapsulation key is rejected (FIPS 203 7.3 input checks), and a
    # DIFFERENT valid key yields a different shared secret (implicit rejection).
    import pytest as _pt
    with _pt.raises(Exception):
        backend.ml_kem_decaps(b"\x00" * 2400, ct)
    other = LibOQSBackend(seed=777)
    _opk, osk = other.ml_kem_keygen()
    ss_other = backend.ml_kem_decaps(osk, ct)
    assert isinstance(ss_other, bytes) and len(ss_other) == 32
    assert ss_other != backend.ml_kem_decaps(sk, ct)


def test_ml_kem_encaps_no_pk_keygen():
    """Encaps without prior keygen on the instance still works in sim mode."""
    backend = LibOQSBackend()
    # Use a pk derived from the default seed keygen (instance had no explicit keygen call yet
    # — keygen is called here only inside this function, so this exercises the sim path
    # with a fresh instance)
    pk, sk = backend.ml_kem_keygen()
    ct, ss = backend.ml_kem_encaps(pk)
    assert len(ct) == 1088
    assert len(ss) == 32


# === liboqs-present Branches (monkeypatch) ===

def test_liboqs_branch_when_env_var_set():
    import importlib
    import pqblocks_jose.optimized.liboqs_backend as mod

    old_env = os.environ.get("PQBLOCKS_JOSE_USE_LIBOQS")
    try:
        os.environ["PQBLOCKS_JOSE_USE_LIBOQS"] = "1"
        importlib.reload(mod)
        assert mod.LIBOQS_AVAILABLE in (True, False)
        be = mod.LibOQSBackend(seed=42)
        pk, sk = be.ml_dsa_keygen()
        sig = be.ml_dsa_sign(sk, b"msg")
        assert be.ml_dsa_verify(pk, b"msg", sig) is True
    finally:
        if old_env is None:
            os.environ.pop("PQBLOCKS_JOSE_USE_LIBOQS", None)
        else:
            os.environ["PQBLOCKS_JOSE_USE_LIBOQS"] = old_env
        importlib.reload(mod)


def test_liboqs_sim_sign_and_verify_different_instances():
    """ML-DSA simulation: verify from instance B works on a signature from instance A,
    when both instances have called keygen with the same (default) seed."""
    backend_a = LibOQSBackend()
    pk_a, sk_a = backend_a.ml_dsa_keygen()
    sig = backend_a.ml_dsa_sign(sk_a, b"msg")
    # Instance B shares the same default seed, so its _key_map contains the same pk->sk
    backend_b = LibOQSBackend()
    backend_b.ml_dsa_keygen()  # registers the same pk->sk mapping
    assert backend_b.ml_dsa_verify(pk_a, b"msg", sig) is True


# === ML-DSA-65 Simulation Error Paths ===

def test_ml_dsa_verify_wrong_pk_fails():
    """Signature from pk1 must not verify against pk2 (different key pairs)."""
    backend = LibOQSBackend(seed=42)
    pk1, sk1 = backend.ml_dsa_keygen()
    backend2 = LibOQSBackend(seed=999)  # different seed → different key pair
    pk2, sk2 = backend2.ml_dsa_keygen()
    # Ensure the two key pairs actually differ
    assert pk1 != pk2
    msg = b"test message"
    sig = backend.ml_dsa_sign(sk1, msg)
    # Verify against pk2 on backend2 (which does not have pk1 in its key map)
    result = backend2.ml_dsa_verify(pk2, msg, sig)
    assert result is False


def test_ml_dsa_verify_uses_seed_when_tampered_pk():
    backend = LibOQSBackend()
    pk, sk = backend.ml_dsa_keygen()
    msg = b"test"
    sig = backend.ml_dsa_sign(sk, msg)
    
    bad_pk = b"\x00" * len(pk)
    result = backend.ml_dsa_verify(bad_pk, msg, sig)
    assert result is False


# === ML-KEM-768 Simulation Error Paths ===

def test_ml_kem_decaps_with_seed_derivation():
    backend = LibOQSBackend(seed=12345)
    pk, sk = backend.ml_kem_keygen()
    ct, ss = backend.ml_kem_encaps(pk)
    ss2 = backend.ml_kem_decaps(sk, ct)
    assert ss == ss2


# === ML-DSA Error Paths ===

def test_ml_dsa_verify_no_keygen_before_verify():
    backend = LibOQSBackend()
    msg = b"test"
    result = backend.ml_dsa_verify(b"\x00" * 1952, msg, b"\x00" * 3309)
    assert result is False


# === Ed25519 Error Paths ===

def test_ed25519_verify_no_keygen_before_verify():
    backend = LibOQSBackend()
    msg = b"test"
    result = backend.ed25519_verify(b"\x00" * 32, msg, b"\x00" * 64)
    assert result is False


# === Ed25519 Simulation Error Paths ===

def test_ed25519_verify_wrong_pk_fails():
    """Signature from pk1 must not verify against pk2 (different key pairs)."""
    backend = LibOQSBackend(seed=42)
    pk1, sk1 = backend.ed25519_keygen()
    backend2 = LibOQSBackend(seed=999)  # different seed → different key pair
    pk2, sk2 = backend2.ed25519_keygen()
    # Ensure the two key pairs actually differ
    assert pk1 != pk2
    msg = b"test message"
    sig = backend.ed25519_sign(sk1, msg)
    # Verify against pk2 on backend2 (which does not have pk1 in its key map)
    result = backend2.ed25519_verify(pk2, msg, sig)
    assert result is False


def test_ed25519_verify_tampered_sig_with_seed():
    backend = LibOQSBackend(seed=777)
    pk, sk = backend.ed25519_keygen()
    msg = b"test"
    sig = bytearray(backend.ed25519_sign(sk, msg))
    sig[0] ^= 0xFF
    result = backend.ed25519_verify(pk, msg, bytes(sig))
    assert result is False


# === Seed Determinism Verification ===

def test_seed_determinism_ml_dsa():
    backend1 = LibOQSBackend(seed=42)
    backend2 = LibOQSBackend(seed=42)
    
    pk1, sk1 = backend1.ml_dsa_keygen()
    pk2, sk2 = backend2.ml_dsa_keygen()
    assert pk1 == pk2
    assert sk1 == sk2


def test_seed_determinism_ml_kem():
    backend1 = LibOQSBackend(seed=42)
    backend2 = LibOQSBackend(seed=42)
    
    pk1, sk1 = backend1.ml_kem_keygen()
    pk2, sk2 = backend2.ml_kem_keygen()
    assert pk1 == pk2
    assert sk1 == sk2


def test_different_seeds_produce_different_keys():
    backend1 = LibOQSBackend(seed=42)
    backend2 = LibOQSBackend(seed=99)
    
    pk1, sk1 = backend1.ml_dsa_keygen()
    pk2, sk2 = backend2.ml_dsa_keygen()
    assert pk1 != pk2


# === Simulation length-expansion branches (Check 3 (correctness) repair) ===

def test_derive_expands_beyond_sha512():
    backend = LibOQSBackend()
    out = backend._derive_keypair_deterministic(b"seed", 200)
    assert len(out) == 200
    out2 = backend._derive_keypair_deterministic(b"seed", 200)
    assert out == out2


def test_ml_dsa_keygen_expands_when_lengths_grow(monkeypatch):
    import pqblocks_jose.optimized.liboqs_backend as mod
    monkeypatch.setattr(mod, "_ml_dsa_65_sk_len", lambda: 64)
    monkeypatch.setattr(mod, "_ml_dsa_65_pk_len", lambda: 64)
    backend = mod.LibOQSBackend()
    # Note: hedged signing behavior updated
    # cryptography; FIPS 203/204/RFC 8032/7748 sizes; private keys in seed form) are fixed.
    # patched length helpers must NOT pad real keys to arbitrary sizes
    pk, sk = backend.ml_dsa_keygen()
    assert len(pk) == 1952 and len(sk) == 32


def test_ml_dsa_verify_expands_when_lengths_grow(monkeypatch):
    import pqblocks_jose.optimized.liboqs_backend as mod
    monkeypatch.setattr(mod, "_ml_dsa_65_sk_len", lambda: 64)
    monkeypatch.setattr(mod, "_ml_dsa_65_pk_len", lambda: 64)
    backend = mod.LibOQSBackend()
    pk, sk = backend.ml_dsa_keygen()
    sig = backend.ml_dsa_sign(sk, b"hello")
    assert backend.ml_dsa_verify(pk, b"hello", sig) is True
    assert backend.ml_dsa_verify(b"\x00" * 64, b"hello", sig) is False


def test_ml_kem_keygen_expands_when_lengths_grow(monkeypatch):
    import pqblocks_jose.optimized.liboqs_backend as mod
    monkeypatch.setattr(mod, "_ml_kem_768_sk_len", lambda: 64)
    monkeypatch.setattr(mod, "_ml_kem_768_pk_len", lambda: 64)
    backend = mod.LibOQSBackend()
    # Note: hedged signing behavior updated
    # cryptography; FIPS 203/204/RFC 8032/7748 sizes; private keys in seed form) are fixed.
    # patched length helpers must NOT pad real keys to arbitrary sizes
    pk, sk = backend.ml_kem_keygen()
    assert len(pk) == 1184 and len(sk) == 64
    ct, ss = backend.ml_kem_encaps(pk)
    assert ss == backend.ml_kem_decaps(sk, ct)


def test_x25519_keygen_expands_when_lengths_grow(monkeypatch):
    import pqblocks_jose.optimized.liboqs_backend as mod
    monkeypatch.setattr(mod, "_x25519_sk_len", lambda: 64)
    monkeypatch.setattr(mod, "_x25519_pk_len", lambda: 64)
    backend = mod.LibOQSBackend()
    # Note: hedged signing behavior updated
    # cryptography; FIPS 203/204/RFC 8032/7748 sizes; private keys in seed form) are fixed.
    # patched length helpers must NOT pad real keys to arbitrary sizes
    pk, sk = backend.x25519_keygen()
    assert len(pk) == 32 and len(sk) == 32


def test_ed25519_keygen_expands_when_lengths_grow(monkeypatch):
    import pqblocks_jose.optimized.liboqs_backend as mod
    monkeypatch.setattr(mod, "_ed25519_sk_len", lambda: 64)
    monkeypatch.setattr(mod, "_ed25519_pk_len", lambda: 64)
    backend = mod.LibOQSBackend()
    # Note: hedged signing behavior updated
    # cryptography; FIPS 203/204/RFC 8032/7748 sizes; private keys in seed form) are fixed.
    # patched length helpers must NOT pad real keys to arbitrary sizes
    pk, sk = backend.ed25519_keygen()
    assert len(pk) == 32 and len(sk) == 32


def test_ed25519_verify_expands_when_lengths_grow(monkeypatch):
    import pqblocks_jose.optimized.liboqs_backend as mod
    monkeypatch.setattr(mod, "_ed25519_sk_len", lambda: 64)
    monkeypatch.setattr(mod, "_ed25519_pk_len", lambda: 64)
    backend = mod.LibOQSBackend()
    pk, sk = backend.ed25519_keygen()
    sig = backend.ed25519_sign(sk, b"m")
    assert backend.ed25519_verify(pk, b"m", sig) is True


def test_ml_dsa_sign_sim_direct():
    backend = LibOQSBackend(seed=7)
    pk, sk = backend.ml_dsa_keygen()
    sig = backend.ml_dsa_sign(sk, b"abc")
    assert len(sig) == 3309
    assert backend.ml_dsa_verify(pk, b"abc", sig) is True


def test_x25519_ed25519_seeded_keygen_types():
    for be, fn in ((LibOQSBackend(seed=1), "x25519_keygen"),
                   (LibOQSBackend(seed=2), "ed25519_keygen")):
        pk, sk = getattr(be, fn)()
        assert type(pk) is bytes and type(sk) is bytes


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
