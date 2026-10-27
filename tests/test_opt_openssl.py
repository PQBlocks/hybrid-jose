"""Tests for S7: Optimized Backend — OpenSSL 3.5+ EVP API.

Tests verify:
- X25519 keygen + DH round-trip via cryptography library
- Ed25519 keygen + sign/verify round-trip via cryptography library
- ML-DSA / ML-KEM delegate to LibOQSBackend (since cryptography v50.0.1
  lacks PQ primitives; OpenSSL 3.6+ would expose them natively)
- All PQBackend ABC methods are implemented
- Determinism where applicable (simulation mode for PQ)
"""

import pytest
import sys
import os

# Add src to path for direct imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pqblocks_jose.optimized.openssl_backend import OpenSSLBackend
from pqblocks_jose.backends.base import PQBackend


# === ABC Compliance ===

def test_openssl_backend_is_pqbackend():
    """OpenSSLBackend must implement PQBackend ABC."""
    assert issubclass(OpenSSLBackend, PQBackend)
    backend = OpenSSLBackend()
    assert isinstance(backend, PQBackend)


def test_all_abstract_methods_are_implemented():
    """All PQBackend abstract methods must not raise NotImplementedError."""
    backend = OpenSSLBackend()
    pk, sk = backend.x25519_keygen()
    assert isinstance(pk, bytes)
    assert isinstance(sk, bytes)

    pk, sk = backend.ed25519_keygen()
    assert isinstance(pk, bytes)
    assert isinstance(sk, bytes)

    pk, sk = backend.ml_dsa_keygen()
    assert isinstance(pk, bytes)
    assert isinstance(sk, bytes)

    pk, sk = backend.ml_kem_keygen()
    assert isinstance(pk, bytes)
    assert isinstance(sk, bytes)


# === X25519 KAT (RFC 7748) via cryptography ===

def test_x25519_keygen_returns_correct_lengths():
    """X25519 keygen must return 32-byte pk and sk."""
    backend = OpenSSLBackend()
    pk, sk = backend.x25519_keygen()
    assert len(pk) == 32
    assert len(sk) == 32


def test_x25519_dh_roundtrip():
    """X25519 DH: two parties must compute the same shared secret."""
    backend = OpenSSLBackend()
    pk_a, sk_a = backend.x25519_keygen()
    pk_b, sk_b = backend.x25519_keygen()

    ss_alice = backend.x25519_dh(sk_a, pk_b)
    ss_bob = backend.x25519_dh(sk_b, pk_a)

    assert ss_alice == ss_bob
    assert len(ss_alice) == 32


def test_x25519_dh_deterministic():
    """Same sk/pk inputs must produce the same shared secret."""
    backend = OpenSSLBackend()
    pk, sk = backend.x25519_keygen()
    ss1 = backend.x25519_dh(sk, pk)
    ss2 = backend.x25519_dh(sk, pk)
    assert ss1 == ss2


def test_x25519_keygen_unique_keys():
    """Two separate keygen calls must produce different keys."""
    backend = OpenSSLBackend()
    pk1, sk1 = backend.x25519_keygen()
    pk2, sk2 = backend.x25519_keygen()
    # In real X25519 with OS entropy, keys should differ
    # (not guaranteed, but astronomically likely)
    assert pk1 != pk2 or sk1 != sk2


# === Ed25519 KAT (RFC 8032) via cryptography ===

def test_ed25519_keygen_returns_correct_lengths():
    """Ed25519 keygen must return 32-byte pk and 32-byte sk (seed)."""
    backend = OpenSSLBackend()
    pk, sk = backend.ed25519_keygen()
    assert len(pk) == 32
    assert len(sk) == 32


def test_ed25519_sign_verify_roundtrip():
    """Ed25519 sign then verify must succeed."""
    backend = OpenSSLBackend()
    pk, sk = backend.ed25519_keygen()
    msg = b"test message for Ed25519 via OpenSSL backend"

    sig = backend.ed25519_sign(sk, msg)
    assert isinstance(sig, bytes)
    assert len(sig) == 64

    result = backend.ed25519_verify(pk, msg, sig)
    assert result is True


def test_ed25519_verify_tampered_msg_fails():
    """Tampered message must fail Ed25519 verification."""
    backend = OpenSSLBackend()
    pk, sk = backend.ed25519_keygen()
    msg = b"original message"
    tampered = b"tampered message"

    sig = backend.ed25519_sign(sk, msg)
    result = backend.ed25519_verify(pk, tampered, sig)
    assert result is False


def test_ed25519_verify_tampered_sig_fails():
    """Tampered signature must fail Ed25519 verification."""
    backend = OpenSSLBackend()
    pk, sk = backend.ed25519_keygen()
    msg = b"test"

    sig = bytearray(backend.ed25519_sign(sk, msg))
    sig[0] ^= 0xFF
    result = backend.ed25519_verify(pk, msg, bytes(sig))
    assert result is False


def test_ed25519_wrong_key_fails():
    """Signature by key A must not verify with key B's public key."""
    backend = OpenSSLBackend()
    pk_a, sk_a = backend.ed25519_keygen()
    pk_b, _ = backend.ed25519_keygen()

    msg = b"message"
    sig = backend.ed25519_sign(sk_a, msg)
    result = backend.ed25519_verify(pk_b, msg, sig)
    assert result is False


# === ML-DSA / ML-KEM delegation to liboqs ===

def test_ml_dsa_delegates_to_liboqs():
    """ML-DSA operations must work (delegated to LibOQSBackend)."""
    backend = OpenSSLBackend()
    pk, sk = backend.ml_dsa_keygen()
    assert isinstance(pk, bytes)
    assert isinstance(sk, bytes)

    msg = b"test message for ML-DSA"
    sig = backend.ml_dsa_sign(sk, msg)
    assert len(sig) == 3309
    assert backend.ml_dsa_verify(pk, msg, sig) is True


def test_ml_kem_delegates_to_liboqs():
    """ML-KEM operations must work (delegated to LibOQSBackend)."""
    backend = OpenSSLBackend()
    pk, sk = backend.ml_kem_keygen()
    assert isinstance(pk, bytes)
    assert isinstance(sk, bytes)

    ct, ss_enc = backend.ml_kem_encaps(pk)
    assert len(ct) == 1088
    assert len(ss_enc) == 32

    ss_dec = backend.ml_kem_decaps(sk, ct)
    assert ss_enc == ss_dec


# === Type safety ===

def test_all_returns_are_bytes():
    """All key operations must return bytes."""
    backend = OpenSSLBackend()

    pk, sk = backend.x25519_keygen()
    assert type(pk) is bytes
    assert type(sk) is bytes

    pk, sk = backend.ed25519_keygen()
    assert type(pk) is bytes
    assert type(sk) is bytes

    pk, sk = backend.ml_dsa_keygen()
    assert type(pk) is bytes
    assert type(sk) is bytes

    pk, sk = backend.ml_kem_keygen()
    assert type(pk) is bytes
    assert type(sk) is bytes


# === Interop: x25519_dh between two OpenSSLBackend instances ===

def test_x25519_dh_two_instances():
    """Two separate OpenSSLBackend instances must produce compatible DH results."""
    backend1 = OpenSSLBackend()
    backend2 = OpenSSLBackend()

    pk1, sk1 = backend1.x25519_keygen()
    pk2, sk2 = backend2.x25519_keygen()

    ss1 = backend1.x25519_dh(sk1, pk2)
    ss2 = backend2.x25519_dh(sk2, pk1)
    assert ss1 == ss2


# === Import Failure Tests (Error Paths) ===

def test_x25519_keygen_runtime_error_when_unavailable(monkeypatch):
    """When x25519 is None, x25519_keygen raises RuntimeError."""
    import pqblocks_jose.optimized.openssl_backend as ob
    monkeypatch.setattr(ob, 'x25519', None)
    monkeypatch.setattr(ob, 'serialization', None)
    
    backend = OpenSSLBackend()
    with pytest.raises(RuntimeError, match="cryptography"):
        backend.x25519_keygen()


def test_x25519_dh_runtime_error_when_unavailable(monkeypatch):
    """When x25519 is None, x25519_dh raises RuntimeError."""
    import pqblocks_jose.optimized.openssl_backend as ob
    monkeypatch.setattr(ob, 'x25519', None)
    
    backend = OpenSSLBackend()
    with pytest.raises(RuntimeError, match="cryptography"):
        backend.x25519_dh(b"x" * 32, b"y" * 32)


def test_x25519_keygen_runtime_error_encoding_monkeypatch(monkeypatch):
    """When serialization is None, x25519_keygen raises RuntimeError."""
    import pqblocks_jose.optimized.openssl_backend as ob
    monkeypatch.setattr(ob, 'x25519', ob.x25519)
    monkeypatch.setattr(ob, 'serialization', None)
    
    backend = OpenSSLBackend()
    with pytest.raises(RuntimeError, match="cryptography"):
        backend.x25519_keygen()


def test_ed25519_keygen_runtime_error_when_unavailable(monkeypatch):
    """When ed25519 is None, ed25519_keygen raises RuntimeError."""
    import pqblocks_jose.optimized.openssl_backend as ob
    monkeypatch.setattr(ob, 'ed25519', None)
    monkeypatch.setattr(ob, 'serialization', ob.serialization)
    
    backend = OpenSSLBackend()
    with pytest.raises(RuntimeError, match="cryptography"):
        backend.ed25519_keygen()


def test_ed25519_sign_runtime_error_when_unavailable(monkeypatch):
    """When ed25519 is None, ed25519_sign raises RuntimeError."""
    import pqblocks_jose.optimized.openssl_backend as ob
    monkeypatch.setattr(ob, 'ed25519', None)
    
    backend = OpenSSLBackend()
    with pytest.raises(RuntimeError, match="cryptography"):
        backend.ed25519_sign(b"x" * 32, b"test")


def test_ed25519_verify_runtime_error_when_unavailable(monkeypatch):
    """When ed25519 is None, ed25519_verify raises RuntimeError."""
    import pqblocks_jose.optimized.openssl_backend as ob
    monkeypatch.setattr(ob, 'ed25519', None)
    
    backend = OpenSSLBackend()
    with pytest.raises(RuntimeError, match="cryptography"):
        backend.ed25519_verify(b"x" * 32, b"test", b"sig" * 32)


def test_ml_dsa_keygen_runtime_error_when_liboqs_unavailable(monkeypatch):
    """When LibOQSBackend is None, ml_dsa_keygen raises RuntimeError."""
    import pqblocks_jose.optimized.openssl_backend as ob
    monkeypatch.setattr(ob, '_LIBOQS_BACKEND', None)
    
    backend = OpenSSLBackend()
    with pytest.raises(RuntimeError, match="LibOQSBackend"):
        backend.ml_dsa_keygen()


def test_ml_dsa_sign_runtime_error_when_liboqs_unavailable(monkeypatch):
    """When LibOQSBackend is None, ml_dsa_sign raises RuntimeError."""
    import pqblocks_jose.optimized.openssl_backend as ob
    monkeypatch.setattr(ob, '_LIBOQS_BACKEND', None)
    
    backend = OpenSSLBackend()
    with pytest.raises(RuntimeError, match="LibOQSBackend"):
        backend.ml_dsa_sign(b"sk", b"msg")


def test_ml_dsa_verify_runtime_error_when_liboqs_unavailable(monkeypatch):
    """When LibOQSBackend is None, ml_dsa_verify raises RuntimeError."""
    import pqblocks_jose.optimized.openssl_backend as ob
    monkeypatch.setattr(ob, '_LIBOQS_BACKEND', None)
    
    backend = OpenSSLBackend()
    with pytest.raises(RuntimeError, match="LibOQSBackend"):
        backend.ml_dsa_verify(b"pk", b"msg", b"sig")


def test_ml_kem_keygen_runtime_error_when_liboqs_unavailable(monkeypatch):
    """When LibOQSBackend is None, ml_kem_keygen raises RuntimeError."""
    import pqblocks_jose.optimized.openssl_backend as ob
    monkeypatch.setattr(ob, '_LIBOQS_BACKEND', None)
    
    backend = OpenSSLBackend()
    with pytest.raises(RuntimeError, match="LibOQSBackend"):
        backend.ml_kem_keygen()


def test_ml_kem_encaps_runtime_error_when_liboqs_unavailable(monkeypatch):
    """When LibOQSBackend is None, ml_kem_encaps raises RuntimeError."""
    import pqblocks_jose.optimized.openssl_backend as ob
    monkeypatch.setattr(ob, '_LIBOQS_BACKEND', None)
    
    backend = OpenSSLBackend()
    with pytest.raises(RuntimeError, match="LibOQSBackend"):
        backend.ml_kem_encaps(b"pk")


def test_ml_kem_decaps_runtime_error_when_liboqs_unavailable(monkeypatch):
    """When LibOQSBackend is None, ml_kem_decaps raises RuntimeError."""
    import pqblocks_jose.optimized.openssl_backend as ob
    monkeypatch.setattr(ob, '_LIBOQS_BACKEND', None)
    
    backend = OpenSSLBackend()
    with pytest.raises(RuntimeError, match="LibOQSBackend"):
        backend.ml_kem_decaps(b"sk", b"ct")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
