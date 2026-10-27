"""The only place pqblocks-jose touches post-quantum cryptography.

Every PQ operation goes through pyca/cryptography's ML-DSA (FIPS 204) and
ML-KEM (FIPS 203) - a maintained, OpenSSL-backed implementation. Nothing here
implements a primitive. Until 2026-10-07 the product simulated both (ML-DSA
"verify" compared the signature with a hash of the message, using no key), so
the rule for this file is absolute: never simulate a primitive, never write one.

Private keys are FIPS seeds - 32 bytes (ML-DSA, xi) and 64 bytes (ML-KEM,
d || z) - which is how pyca represents them and what the IETF key-format
drafts prefer over expanded keys.
"""
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem, x25519

MLDSA65_SEED = 32
MLDSA65_PK = 1952
MLDSA65_SIG = 3309
MLKEM768_SEED = 64
MLKEM768_PK = 1184
MLKEM768_CT = 1088
XWING_LABEL = bytes.fromhex("5c2e2f2f5e5c")      # draft-connolly-cfrg-xwing-kem, "\.//^\"

_RAW = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def mldsa65_keypair(seed: bytes) -> tuple[bytes, bytes]:
    """(public key, private seed) from a 32-byte seed (FIPS 204 KeyGen_internal)."""
    if len(seed) != MLDSA65_SEED:
        raise ValueError("ML-DSA-65 seed must be 32 bytes")
    return mldsa.MLDSA65PrivateKey.from_seed_bytes(seed).public_key().public_bytes(*_RAW), seed


def mldsa65_sign(seed: bytes, message: bytes, context: bytes = b"") -> bytes:
    """FIPS 204 hedged ML-DSA.Sign on pyca/OpenSSL (constant-time). Deterministic
    signing in pure-Python dilithium-py was removed after review (timing side channel)."""
    return mldsa.MLDSA65PrivateKey.from_seed_bytes(seed).sign(message, context or None)


def mldsa65_verify(public_key: bytes, message: bytes, signature: bytes, context: bytes = b"") -> bool:
    try:
        mldsa.MLDSA65PublicKey.from_public_bytes(public_key).verify(signature, message, context or None)
        return True
    except (InvalidSignature, ValueError):
        return False


def mlkem768_keypair(seed: bytes) -> tuple[bytes, bytes]:
    """(encapsulation key, private seed) from a 64-byte seed d || z (FIPS 203)."""
    if len(seed) != MLKEM768_SEED:
        raise ValueError("ML-KEM-768 seed must be 64 bytes (d || z)")
    return mlkem.MLKEM768PrivateKey.from_seed_bytes(seed).public_key().public_bytes(*_RAW), seed


def xwing_combiner(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> bytes:
    """X-Wing combiner, verbatim from draft-connolly-cfrg-xwing-kem 5.3. It binds
    the X25519 ciphertext and recipient key; the former SHA3(ss_X || ss_M) did not."""
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + XWING_LABEL).digest()


def hybrid_encapsulate(pk_x: bytes, pk_m: bytes) -> tuple[bytes, bytes, bytes]:
    """Fresh randomness every call. Returns (shared secret, ct_X, ct_M)."""
    eph = x25519.X25519PrivateKey.generate()
    ct_x = eph.public_key().public_bytes(*_RAW)
    ss_x = eph.exchange(x25519.X25519PublicKey.from_public_bytes(pk_x))
    ss_m, ct_m = mlkem.MLKEM768PublicKey.from_public_bytes(pk_m).encapsulate()
    return xwing_combiner(ss_m, ss_x, ct_x, pk_x), ct_x, ct_m


def hybrid_decapsulate(sk_x: bytes, seed_m: bytes, ct_x: bytes, ct_m: bytes) -> bytes:
    """Needs the recipient's PRIVATE keys - there is no public-key path."""
    priv_x = x25519.X25519PrivateKey.from_private_bytes(sk_x)
    pk_x = priv_x.public_key().public_bytes(*_RAW)
    ss_x = priv_x.exchange(x25519.X25519PublicKey.from_public_bytes(ct_x))
    ss_m = mlkem.MLKEM768PrivateKey.from_seed_bytes(seed_m).decapsulate(ct_m)
    return xwing_combiner(ss_m, ss_x, ct_x, pk_x)
