"""Tests for PQ Backend ABC and backend stubs.

Tests that:
1. PQBackend abstract class cannot be instantiated
2. All abstract methods raise NotImplementedError
3. LibOQSBackend and OpenSSLBackend stubs work as expected
4. get_backend() returns appropriate backends
"""

import pytest
from pqblocks_jose.backends.base import PQBackend
from pqblocks_jose.backends.liboqs_backend import LibOQSBackend
from pqblocks_jose.backends.openssl_backend import OpenSSLBackend
from pqblocks_jose.backends import get_backend


class ConcreteBackend(PQBackend):
    """Minimal concrete implementation for testing ABC behavior."""

    def ml_dsa_keygen(self):
        return super().ml_dsa_keygen()

    def ml_dsa_sign(self, sk, msg, ctx):
        return super().ml_dsa_sign(sk, msg, ctx)

    def ml_dsa_verify(self, pk, msg, sig, ctx):
        return super().ml_dsa_verify(pk, msg, sig, ctx)

    def ml_kem_keygen(self):
        return super().ml_kem_keygen()

    def ml_kem_encaps(self, pk):
        return super().ml_kem_encaps(pk)

    def ml_kem_decaps(self, sk, ct):
        return super().ml_kem_decaps(sk, ct)

    def x25519_keygen(self):
        return super().x25519_keygen()

    def x25519_dh(self, sk, pk):
        return super().x25519_dh(sk, pk)

    def ed25519_keygen(self):
        return super().ed25519_keygen()

    def ed25519_sign(self, sk, msg):
        return super().ed25519_sign(sk, msg)

    def ed25519_verify(self, pk, msg, sig):
        return super().ed25519_verify(pk, msg, sig)


def test_backend_abc_cannot_be_instantiated():
    """PQBackend cannot be instantiated directly due to abstract methods."""
    with pytest.raises(TypeError):
        PQBackend()


def test_ml_dsa_keygen_raises():
    """ConcreteBackend.ml_dsa_keygen raises NotImplementedError."""
    with pytest.raises(NotImplementedError):
        ConcreteBackend().ml_dsa_keygen()


def test_ml_dsa_sign_raises():
    """ConcreteBackend.ml_dsa_sign raises NotImplementedError."""
    with pytest.raises(NotImplementedError):
        ConcreteBackend().ml_dsa_sign(b"sk", b"msg", b"")


def test_ml_dsa_verify_raises():
    """ConcreteBackend.ml_dsa_verify raises NotImplementedError."""
    with pytest.raises(NotImplementedError):
        ConcreteBackend().ml_dsa_verify(b"pk", b"msg", b"sig", b"")


def test_ml_kem_keygen_raises():
    """ConcreteBackend.ml_kem_keygen raises NotImplementedError."""
    with pytest.raises(NotImplementedError):
        ConcreteBackend().ml_kem_keygen()


def test_ml_kem_encaps_raises():
    """ConcreteBackend.ml_kem_encaps raises NotImplementedError."""
    with pytest.raises(NotImplementedError):
        ConcreteBackend().ml_kem_encaps(b"pk")


def test_ml_kem_decaps_raises():
    """ConcreteBackend.ml_kem_decaps raises NotImplementedError."""
    with pytest.raises(NotImplementedError):
        ConcreteBackend().ml_kem_decaps(b"sk", b"ct")


def test_x25519_keygen_raises():
    """ConcreteBackend.x25519_keygen raises NotImplementedError."""
    with pytest.raises(NotImplementedError):
        ConcreteBackend().x25519_keygen()


def test_x25519_dh_raises():
    """ConcreteBackend.x25519_dh raises NotImplementedError."""
    with pytest.raises(NotImplementedError):
        ConcreteBackend().x25519_dh(b"sk", b"pk")


def test_ed25519_keygen_raises():
    """ConcreteBackend.ed25519_keygen raises NotImplementedError."""
    with pytest.raises(NotImplementedError):
        ConcreteBackend().ed25519_keygen()


def test_ed25519_sign_raises():
    """ConcreteBackend.ed25519_sign raises NotImplementedError."""
    with pytest.raises(NotImplementedError):
        ConcreteBackend().ed25519_sign(b"sk", b"msg")


def test_ed25519_verify_raises():
    """ConcreteBackend.ed25519_verify raises NotImplementedError."""
    with pytest.raises(NotImplementedError):
        ConcreteBackend().ed25519_verify(b"pk", b"msg", b"sig")


# === LibOQS Backend stub tests ===


def test_liboqs_backend_is_pqbackend():
    """LibOQSBackend is a subclass of PQBackend."""
    assert issubclass(LibOQSBackend, PQBackend)


def test_liboqs_backend_ml_dsa_keygen_raises():
    """LibOQSBackend.ml_dsa_keygen raises NotImplementedError."""
    backend = LibOQSBackend()
    with pytest.raises(NotImplementedError, match="liboqs ML-DSA-65 keygen not implemented"):
        backend.ml_dsa_keygen()


def test_liboqs_backend_ml_dsa_sign_raises():
    """LibOQSBackend.ml_dsa_sign raises NotImplementedError."""
    backend = LibOQSBackend()
    with pytest.raises(NotImplementedError, match="liboqs ML-DSA-65 sign not implemented"):
        backend.ml_dsa_sign(b"sk", b"msg")


def test_liboqs_backend_ml_dsa_verify_raises():
    """LibOQSBackend.ml_dsa_verify raises NotImplementedError."""
    backend = LibOQSBackend()
    with pytest.raises(NotImplementedError, match="liboqs ML-DSA-65 verify not implemented"):
        backend.ml_dsa_verify(b"pk", b"msg", b"sig")


def test_liboqs_backend_ml_kem_keygen_raises():
    """LibOQSBackend.ml_kem_keygen raises NotImplementedError."""
    backend = LibOQSBackend()
    with pytest.raises(NotImplementedError, match="liboqs ML-KEM-768 keygen not implemented"):
        backend.ml_kem_keygen()


def test_liboqs_backend_ml_kem_encaps_raises():
    """LibOQSBackend.ml_kem_encaps raises NotImplementedError."""
    backend = LibOQSBackend()
    with pytest.raises(NotImplementedError, match="liboqs ML-KEM-768 encaps not implemented"):
        backend.ml_kem_encaps(b"pk")


def test_liboqs_backend_ml_kem_decaps_raises():
    """LibOQSBackend.ml_kem_decaps raises NotImplementedError."""
    backend = LibOQSBackend()
    with pytest.raises(NotImplementedError, match="liboqs ML-KEM-768 decaps not implemented"):
        backend.ml_kem_decaps(b"sk", b"ct")


def test_liboqs_backend_x25519_keygen_raises():
    """LibOQSBackend.x25519_keygen raises NotImplementedError."""
    backend = LibOQSBackend()
    with pytest.raises(NotImplementedError, match="liboqs X25519 keygen not implemented"):
        backend.x25519_keygen()


def test_liboqs_backend_x25519_dh_raises():
    """LibOQSBackend.x25519_dh raises NotImplementedError."""
    backend = LibOQSBackend()
    with pytest.raises(NotImplementedError, match="liboqs X25519 DH not implemented"):
        backend.x25519_dh(b"sk", b"pk")


def test_liboqs_backend_ed25519_keygen_raises():
    """LibOQSBackend.ed25519_keygen raises NotImplementedError."""
    backend = LibOQSBackend()
    with pytest.raises(NotImplementedError, match="Ed25519 keygen not implemented"):
        backend.ed25519_keygen()


def test_liboqs_backend_ed25519_sign_raises():
    """LibOQSBackend.ed25519_sign raises NotImplementedError."""
    backend = LibOQSBackend()
    with pytest.raises(NotImplementedError, match="Ed25519 sign not implemented"):
        backend.ed25519_sign(b"sk", b"msg")


def test_liboqs_backend_ed25519_verify_raises():
    """LibOQSBackend.ed25519_verify raises NotImplementedError."""
    backend = LibOQSBackend()
    with pytest.raises(NotImplementedError, match="Ed25519 verify not implemented"):
        backend.ed25519_verify(b"pk", b"msg", b"sig")


# === OpenSSL Backend stub tests ===


def test_openssl_backend_is_pqbackend():
    """OpenSSLBackend is a subclass of PQBackend."""
    assert issubclass(OpenSSLBackend, PQBackend)


def test_openssl_backend_ml_dsa_keygen_raises():
    """OpenSSLBackend.ml_dsa_keygen raises NotImplementedError."""
    backend = OpenSSLBackend()
    with pytest.raises(NotImplementedError, match="OpenSSL ML-DSA-65 keygen not implemented"):
        backend.ml_dsa_keygen()


def test_openssl_backend_ml_dsa_sign_raises():
    """OpenSSLBackend.ml_dsa_sign raises NotImplementedError."""
    backend = OpenSSLBackend()
    with pytest.raises(NotImplementedError, match="OpenSSL ML-DSA-65 sign not implemented"):
        backend.ml_dsa_sign(b"sk", b"msg")


def test_openssl_backend_ml_dsa_verify_raises():
    """OpenSSLBackend.ml_dsa_verify raises NotImplementedError."""
    backend = OpenSSLBackend()
    with pytest.raises(NotImplementedError, match="OpenSSL ML-DSA-65 verify not implemented"):
        backend.ml_dsa_verify(b"pk", b"msg", b"sig")


def test_openssl_backend_ml_kem_keygen_raises():
    """OpenSSLBackend.ml_kem_keygen raises NotImplementedError."""
    backend = OpenSSLBackend()
    with pytest.raises(NotImplementedError, match="OpenSSL ML-KEM-768 keygen not implemented"):
        backend.ml_kem_keygen()


def test_openssl_backend_ml_kem_encaps_raises():
    """OpenSSLBackend.ml_kem_encaps raises NotImplementedError."""
    backend = OpenSSLBackend()
    with pytest.raises(NotImplementedError, match="OpenSSL ML-KEM-768 encaps not implemented"):
        backend.ml_kem_encaps(b"pk")


def test_openssl_backend_ml_kem_decaps_raises():
    """OpenSSLBackend.ml_kem_decaps raises NotImplementedError."""
    backend = OpenSSLBackend()
    with pytest.raises(NotImplementedError, match="OpenSSL ML-KEM-768 decaps not implemented"):
        backend.ml_kem_decaps(b"sk", b"ct")


def test_openssl_backend_x25519_keygen_raises():
    """OpenSSLBackend.x25519_keygen raises NotImplementedError."""
    backend = OpenSSLBackend()
    with pytest.raises(NotImplementedError, match="OpenSSL X25519 keygen not implemented"):
        backend.x25519_keygen()


def test_openssl_backend_x25519_dh_raises():
    """OpenSSLBackend.x25519_dh raises NotImplementedError."""
    backend = OpenSSLBackend()
    with pytest.raises(NotImplementedError, match="OpenSSL X25519 DH not implemented"):
        backend.x25519_dh(b"sk", b"pk")


def test_openssl_backend_ed25519_keygen_raises():
    """OpenSSLBackend.ed25519_keygen raises NotImplementedError."""
    backend = OpenSSLBackend()
    with pytest.raises(NotImplementedError, match="OpenSSL Ed25519 keygen not implemented"):
        backend.ed25519_keygen()


def test_openssl_backend_ed25519_sign_raises():
    """OpenSSLBackend.ed25519_sign raises NotImplementedError."""
    backend = OpenSSLBackend()
    with pytest.raises(NotImplementedError, match="OpenSSL Ed25519 sign not implemented"):
        backend.ed25519_sign(b"sk", b"msg")


def test_openssl_backend_ed25519_verify_raises():
    """OpenSSLBackend.ed25519_verify raises NotImplementedError."""
    backend = OpenSSLBackend()
    with pytest.raises(NotImplementedError, match="OpenSSL Ed25519 verify not implemented"):
        backend.ed25519_verify(b"pk", b"msg", b"sig")


# === get_backend() tests ===


def test_get_backend_ml_dsa_returns_liboqs():
    """get_backend('ml_dsa') returns LibOQSBackend instance."""
    backend = get_backend("ml_dsa")
    assert isinstance(backend, LibOQSBackend)
    assert not isinstance(backend, OpenSSLBackend)


def test_get_backend_ml_kem_returns_liboqs():
    """get_backend('ml_kem') returns LibOQSBackend instance."""
    backend = get_backend("ml_kem")
    assert isinstance(backend, LibOQSBackend)
    assert not isinstance(backend, OpenSSLBackend)


def test_get_backend_x25519_returns_openssl():
    """get_backend('x25519') returns OpenSSLBackend instance."""
    backend = get_backend("x25519")
    assert isinstance(backend, OpenSSLBackend)
    assert not isinstance(backend, LibOQSBackend)


def test_get_backend_ed25519_returns_openssl():
    """get_backend('ed25519') returns OpenSSLBackend instance."""
    backend = get_backend("ed25519")
    assert isinstance(backend, OpenSSLBackend)
    assert not isinstance(backend, LibOQSBackend)


def test_get_backend_unknown_operation_raises_value_error():
    """get_backend with unknown operation raises ValueError."""
    with pytest.raises(ValueError, match="Unknown operation"):
        get_backend("unknown_operation")


def test_get_backend_case_sensitivity():
    """get_backend is case-sensitive: 'ML_DSA' is unknown."""
    with pytest.raises(ValueError, match="Unknown operation"):
        get_backend("ML_DSA")


def test_get_backend_empty_string_raises_value_error():
    """get_backend with empty string raises ValueError."""
    with pytest.raises(ValueError, match="Unknown operation"):
        get_backend("")
