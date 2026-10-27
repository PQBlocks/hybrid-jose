"""Optimized liboqs backend for pqblocks-jose.

This module implements the PQBackend interface using liboqs via CFFI.
It provides actual post-quantum cryptographic operations for ML-DSA-65 and ML-KEM-768.

When liboqs is not available, it falls back to a simulation mode for development/testing.
"""

import os
import hashlib
from typing import Tuple, Optional
from pqblocks_jose.backends.base import PQBackend

# Check if we should use real liboqs or fallback to simulation
# The cffi liboqs path is disabled (review 2026-10-07): it declared X25519/Ed25519 functions liboqs
# does not have, ignored status codes and read Ed25519 success inverted. Real primitives come from
# pyca/cryptography; use liboqs through oqs-python if it is ever needed again.
USE_LIBOQS = False

if USE_LIBOQS:
    try:
        import cffi
        # Initialize CFFI interface
        _ffi = cffi.FFI()
        # Define liboqs functions we need
        _ffi.cdef("""
            // ML-DSA-65 (FIPS 204)
            void OQS_SIG_ml_dsa_65_keypair(unsigned char *public_key, unsigned char *secret_key);
            void OQS_SIG_ml_dsa_65_sign(unsigned char *signature, size_t *signature_len,
                                          const unsigned char *message, size_t message_len,
                                          const unsigned char *secret_key);
            int OQS_SIG_ml_dsa_65_verify(const unsigned char *message, size_t message_len,
                                         const unsigned char *signature, size_t signature_len,
                                         const unsigned char *public_key);
            size_t OQS_SIG_ml_dsa_65_length_secret_key(void);
            size_t OQS_SIG_ml_dsa_65_length_public_key(void);
            size_t OQS_SIG_ml_dsa_65_length_signature(void);

            // ML-KEM-768 (FIPS 203)
            void OQS_KEM_ml_kem_768_keypair(unsigned char *public_key, unsigned char *secret_key);
            int OQS_KEM_ml_kem_768_encaps(unsigned char *ciphertext, unsigned char *shared_secret,
                                          const unsigned char *public_key);
            int OQS_KEM_ml_kem_768_decaps(unsigned char *shared_secret,
                                          const unsigned char *ciphertext, size_t ciphertext_len,
                                          const unsigned char *secret_key);
            size_t OQS_KEM_ml_kem_768_length_secret_key(void);
            size_t OQS_KEM_ml_kem_768_length_public_key(void);
            size_t OQS_KEM_ml_kem_768_length_ciphertext(void);
            size_t OQS_KEM_ml_kem_768_length_shared_secret(void);

            // X25519 (via liboqs)
            void OQS_KEM_x25519_keypair(unsigned char *public_key, unsigned char *secret_key);
            int OQS_KEM_x25519_shared_secret(unsigned char *shared_secret,
                                             const unsigned char *private_key,
                                             const unsigned char *public_key);
            size_t OQS_KEM_x25519_length_secret_key(void);
            size_t OQS_KEM_x25519_length_public_key(void);
            size_t OQS_KEM_x25519_length_shared_secret(void);

            // ED25519 (via liboqs)
            void OQS_SIG_eddsa_25519_sha512_keypair(unsigned char *public_key, unsigned char *secret_key);
            void OQS_SIG_eddsa_25519_sha512_sign(unsigned char *signature, size_t *signature_len,
                                                 const unsigned char *message, size_t message_len,
                                                 const unsigned char *secret_key);
            int OQS_SIG_eddsa_25519_sha512_verify(const unsigned char *message, size_t message_len,
                                                  const unsigned char *signature, size_t signature_len,
                                                  const unsigned char *public_key);
            size_t OQS_SIG_eddsa_25519_sha512_length_secret_key(void);
            size_t OQS_SIG_eddsa_25519_sha512_length_public_key(void);
            size_t OQS_SIG_eddsa_25519_sha512_length_signature(void);
        """)
        
        # Load liboqs library
        _liboqs = _ffi.dlopen("oqs")  # liboqs.so
        
        # Helper functions for key lengths
        def _ml_dsa_65_sk_len():
            try: return _liboqs.OQS_SIG_ml_dsa_65_length_secret_key()
            except Exception: return 4032
        
        def _ml_dsa_65_pk_len():
            try: return _liboqs.OQS_SIG_ml_dsa_65_length_public_key()
            except Exception: return 1952
        
        def _ml_dsa_65_sig_len():
            try: return _liboqs.OQS_SIG_ml_dsa_65_length_signature()
            except Exception: return 3309
        
        def _ml_kem_768_sk_len():
            try: return _liboqs.OQS_KEM_ml_kem_768_length_secret_key()
            except Exception: return 2400
        
        def _ml_kem_768_pk_len():
            try: return _liboqs.OQS_KEM_ml_kem_768_length_public_key()
            except Exception: return 1184
        
        def _ml_kem_768_ct_len():
            try: return _liboqs.OQS_KEM_ml_kem_768_length_ciphertext()
            except Exception: return 1088
        
        def _ml_kem_768_ss_len():
            try: return _liboqs.OQS_KEM_ml_kem_768_length_shared_secret()
            except Exception: return 32
        
        def _x25519_sk_len():
            try: return _liboqs.OQS_KEM_x25519_length_secret_key()
            except Exception: return 32
        
        def _x25519_pk_len():
            try: return _liboqs.OQS_KEM_x25519_length_public_key()
            except Exception: return 32
        
        def _x25519_ss_len():
            try: return _liboqs.OQS_KEM_x25519_length_shared_secret()
            except Exception: return 32
        
        def _ed25519_sk_len():
            try: return _liboqs.OQS_SIG_eddsa_25519_sha512_length_secret_key()
            except Exception: return 32
        
        def _ed25519_pk_len():
            try: return _liboqs.OQS_SIG_eddsa_25519_sha512_length_public_key()
            except Exception: return 32
        
        def _ed25519_sig_len():
            try: return _liboqs.OQS_SIG_eddsa_25519_sha512_length_signature()
            except Exception: return 64
        
        LIBOQS_AVAILABLE = True
        
    except Exception as e:
        # Fallback to simulation if liboqs not available
        USE_LIBOQS = False
        LIBOQS_AVAILABLE = False
        _init_error = str(e)

if not USE_LIBOQS or not LIBOQS_AVAILABLE:
    # Simulation mode for development/testing
    LIBOQS_AVAILABLE = False
    
    def _ml_dsa_65_sk_len(): return 32  # Seed length for deterministic derivation
    def _ml_dsa_65_pk_len(): return 32
    def _ml_dsa_65_sig_len(): return 3309  # From FIPS 204
    
    def _ml_kem_768_sk_len(): return 32
    def _ml_kem_768_pk_len(): return 32
    def _ml_kem_768_ct_len(): return 1088  # From FIPS 203
    def _ml_kem_768_ss_len(): return 32
    
    def _x25519_sk_len(): return 32
    def _x25519_pk_len(): return 32
    def _x25519_ss_len(): return 32
    
    def _ed25519_sk_len(): return 32
    def _ed25519_pk_len(): return 32
    def _ed25519_sig_len(): return 64


from cryptography.hazmat.primitives import serialization as _ser
from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519, mlkem as _mlkem, x25519 as _x25519
from pqblocks_jose import pq as _pq
_RAW = (_ser.Encoding.Raw, _ser.PublicFormat.Raw)
_NO_LIBOQS = ("liboqs is not available - this backend runs real ML-DSA/ML-KEM through liboqs or not at all; "
              "use pqblocks_jose.pq (pyca/cryptography) instead of a simulated primitive")


class LibOQSBackend(PQBackend):
    """liboqs backend for post-quantum cryptographic operations.

    Uses actual liboqs via CFFI when available, falls back to deterministic
    simulation for development/testing when liboqs is not installed.
    """

    def __init__(self, seed: Optional[int] = None):
        """Initialize backend with optional seed for deterministic operations.

        Args:
            seed: Deterministic seed for key generation. If None,
                  operations will be non-deterministic.
        """
        self.seed = seed
        self._last_keygen_seed: Optional[bytes] = None
        # unseeded: one fresh random seed per instance - stable within it, never
        # shared across instances (review 2026-10-07: "None" was a public constant)
        self._instance_seed = __import__("os").urandom(32) if seed is None else None
    
    def _derive_keypair_deterministic(self, seed: bytes, length: int) -> bytes:
        """Derive deterministic key material from seed for reproducibility."""
        # If we have a backend seed, incorporate it
        if self.seed is not None:
            seed = hashlib.sha256(seed + str(self.seed).encode('utf-8')).digest()
        # Use SHA-512 to expand seed to required length
        expanded = hashlib.sha512(seed).digest()
        # Repeat if needed
        while len(expanded) < length:
            expanded += hashlib.sha512(expanded).digest()
        return expanded[:length]
    
    def _derive_keypair_from_seed(self, seed: bytes) -> Tuple[bytes, bytes]:
        """Derive a deterministic keypair from seed."""
        # Use first half for secret key, second half for public key material
        # Then derive actual keys from these
        seed_material = hashlib.sha512(seed).digest()
        sk_seed = seed_material[:32]
        pk_seed = seed_material[32:64]
        sk = self._derive_keypair_deterministic(sk_seed, 32)  # Will expand to needed length
        pk = self._derive_keypair_deterministic(pk_seed, 32)
        return pk, sk
    


    def _seed32(self, label: bytes) -> bytes:
        """32 deterministic bytes for this backend's seed and a label."""
        if self.seed is None:
            return hashlib.sha256(b"pqblocks-jose-backend-v2|" + label + b"|" + self._instance_seed).digest()
        return hashlib.sha256(b"pqblocks-jose-backend-v2|" + label + b"|" + str(self.seed).encode()).digest()

    def ml_dsa_keygen(self) -> Tuple[bytes, bytes]:
        """Generate ML-DSA-65 key pair using liboqs or deterministic simulation."""
        if USE_LIBOQS and LIBOQS_AVAILABLE:
            # Use real liboqs
            sk_len = _ml_dsa_65_sk_len()
            pk_len = _ml_dsa_65_pk_len()
            sk = _ffi.new("unsigned char[]", sk_len)
            pk = _ffi.new("unsigned char[]", pk_len)
            _liboqs.OQS_SIG_ml_dsa_65_keypair(pk, sk)
            return bytes(_ffi.buffer(pk)), bytes(_ffi.buffer(sk))
        else:
            # no liboqs: the same REAL primitive via pyca/cryptography (never a simulation)
            xi = self._seed32(b"ml-dsa-65")
            return _pq.mldsa65_keypair(xi)

    def ml_dsa_sign(self, sk: bytes, msg: bytes, ctx: bytes = b"") -> bytes:
        """Sign message using ML-DSA-65 private key via liboqs or simulation."""
        if len(ctx) != 0:
            raise ValueError("Context must be empty for ML-DSA-65 per RFC 9964")
        
        if USE_LIBOQS and LIBOQS_AVAILABLE:
            # Use real liboqs
            sig_len = _ml_dsa_65_sig_len()
            sig = _ffi.new("unsigned char[]", sig_len)
            sig_len_ptr = _ffi.new("size_t *", sig_len)
            _liboqs.OQS_SIG_ml_dsa_65_sign(sig, sig_len_ptr, msg, len(msg), sk)
            actual_sig_len = sig_len_ptr[0]
            return bytes(_ffi.buffer(sig, actual_sig_len))
        else:
            # no liboqs: the same REAL primitive via pyca/cryptography (never a simulation)
            return _pq.mldsa65_sign(sk, msg)

    def ml_dsa_verify(self, pk: bytes, msg: bytes, sig: bytes, ctx: bytes = b"") -> bool:
        """Verify signature using ML-DSA-65 public key via liboqs or simulation."""
        if len(ctx) != 0:
            raise ValueError("Context must be empty for ML-DSA-65 per RFC 9964")
        
        if USE_LIBOQS and LIBOQS_AVAILABLE:
            # Use real liboqs
            result = _liboqs.OQS_SIG_ml_dsa_65_verify(msg, len(msg), sig, len(sig), pk)
            return result == 0  # OQS_SUCCESS
        else:
            # no liboqs: the same REAL primitive via pyca/cryptography (never a simulation)
            return _pq.mldsa65_verify(pk, msg, sig)

    def ml_kem_keygen(self) -> Tuple[bytes, bytes]:
        """Generate ML-KEM-768 key pair using liboqs or deterministic simulation."""
        if USE_LIBOQS and LIBOQS_AVAILABLE:
            # Use real liboqs
            sk_len = _ml_kem_768_sk_len()
            pk_len = _ml_kem_768_pk_len()
            sk = _ffi.new("unsigned char[]", sk_len)
            pk = _ffi.new("unsigned char[]", pk_len)
            _liboqs.OQS_KEM_ml_kem_768_keypair(pk, sk)
            return bytes(_ffi.buffer(pk)), bytes(_ffi.buffer(sk))
        else:
            # no liboqs: the same REAL primitive via pyca/cryptography (never a simulation)
            return _pq.mlkem768_keypair(self._seed32(b"ml-kem-768-d") + self._seed32(b"ml-kem-768-z"))

    def ml_kem_encaps(self, pk: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate secret using ML-KEM-768 public key via liboqs or simulation."""
        if USE_LIBOQS and LIBOQS_AVAILABLE:
            # Use real liboqs
            ct_len = _ml_kem_768_ct_len()
            ss_len = _ml_kem_768_ss_len()
            ct = _ffi.new("unsigned char[]", ct_len)
            ss = _ffi.new("unsigned char[]", ss_len)
            result = _liboqs.OQS_KEM_ml_kem_768_encaps(ct, ss, pk)
            if result != 0:  # OQS_SUCCESS
                raise RuntimeError("ML-KEM-768 encapsulation failed")
            return bytes(_ffi.buffer(ct)), bytes(_ffi.buffer(ss))
        else:
            # no liboqs: the same REAL primitive via pyca/cryptography (never a simulation)
            ss, ct = _mlkem.MLKEM768PublicKey.from_public_bytes(pk).encapsulate()
            return ct, ss

    def ml_kem_decaps(self, sk: bytes, ct: bytes) -> bytes:
        """Decapsulate secret using ML-KEM-768 private key via liboqs or simulation."""
        if USE_LIBOQS and LIBOQS_AVAILABLE:
            # Use real liboqs
            ss_len = _ml_kem_768_ss_len()
            ss = bytearray(ss_len)
            result = _liboqs.OQS_KEM_ml_kem_768_decaps(ss, ct, len(ct), sk)
            if result != 0:  # OQS_SUCCESS
                raise RuntimeError("ML-KEM-768 decapsulation failed")
            return bytes(ss)
        else:
            # no liboqs: the same REAL primitive via pyca/cryptography (never a simulation)
            return _mlkem.MLKEM768PrivateKey.from_seed_bytes(sk).decapsulate(ct)

    def x25519_keygen(self) -> Tuple[bytes, bytes]:
        """Generate X25519 key pair using liboqs or deterministic simulation."""
        if USE_LIBOQS and LIBOQS_AVAILABLE:
            # Use real liboqs
            sk_len = _x25519_sk_len()
            pk_len = _x25519_pk_len()
            sk = bytearray(sk_len)
            pk = bytearray(pk_len)
            _liboqs.OQS_KEM_x25519_keypair(pk, sk)
            return bytes(pk), bytes(sk)
        else:
            # no liboqs: the same REAL primitive via pyca/cryptography (never a simulation)
            k = _x25519.X25519PrivateKey.from_private_bytes(self._seed32(b"x25519"))
            return k.public_key().public_bytes(*_RAW), k.private_bytes_raw()

    def x25519_dh(self, sk: bytes, pk: bytes) -> bytes:
        """Compute X25519 Diffie-Hellman shared secret using liboqs or simulation."""
        if USE_LIBOQS and LIBOQS_AVAILABLE:
            # Use real liboqs
            ss_len = _x25519_ss_len()
            ss = bytearray(ss_len)
            result = _liboqs.OQS_KEM_x25519_shared_secret(ss, sk, pk)
            if result != 0:  # OQS_SUCCESS
                raise RuntimeError("X25519 Diffie-Hellman failed")
            return bytes(ss)
        else:
            # no liboqs: the same REAL primitive via pyca/cryptography (never a simulation)
            return _x25519.X25519PrivateKey.from_private_bytes(sk).exchange(_x25519.X25519PublicKey.from_public_bytes(pk))

    def ed25519_keygen(self) -> Tuple[bytes, bytes]:
        """Generate Ed25519 key pair using liboqs or deterministic simulation."""
        if USE_LIBOQS and LIBOQS_AVAILABLE:
            # Use real liboqs
            sk_len = _ed25519_sk_len()
            pk_len = _ed25519_pk_len()
            sk = _ffi.new("unsigned char[]", sk_len)
            pk = _ffi.new("unsigned char[]", pk_len)
            _liboqs.OQS_SIG_eddsa_25519_sha512_keypair(pk, sk)
            return bytes(_ffi.buffer(pk)), bytes(_ffi.buffer(sk))
        else:
            # no liboqs: the same REAL primitive via pyca/cryptography (never a simulation)
            k = _ed25519.Ed25519PrivateKey.from_private_bytes(self._seed32(b"ed25519"))
            return k.public_key().public_bytes(*_RAW), k.private_bytes_raw()

    def ed25519_sign(self, sk: bytes, msg: bytes) -> bytes:
        """Sign message using Ed25519 private key via liboqs or simulation."""
        if USE_LIBOQS and LIBOQS_AVAILABLE:
            # Use real liboqs
            sig_len = _ed25519_sig_len()
            sig = _ffi.new("unsigned char[]", sig_len)
            sig_len_ptr = _ffi.new("size_t *", sig_len)
            _liboqs.OQS_SIG_eddsa_25519_sha512_sign(sig, sig_len_ptr, msg, len(msg), sk)
            actual_sig_len = sig_len_ptr[0]
            return bytes(_ffi.buffer(sig, actual_sig_len))
        else:
            # no liboqs: the same REAL primitive via pyca/cryptography (never a simulation)
            return _ed25519.Ed25519PrivateKey.from_private_bytes(sk[:32]).sign(msg)

    def ed25519_verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        """Verify signature using Ed25519 public key via liboqs or simulation."""
        if USE_LIBOQS and LIBOQS_AVAILABLE:
            # Use real liboqs
            result = _liboqs.OQS_SIG_eddsa_25519_sha512_verify(msg, len(msg), sig, len(sig), pk)
            return result == 1  # OQS_SUCCESS
        else:
            # no liboqs: the same REAL primitive via pyca/cryptography (never a simulation)
            try:
                _ed25519.Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
                return True
            except Exception:
                return False
