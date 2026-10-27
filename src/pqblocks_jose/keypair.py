"""Hybrid keypair generation for pqblocks-jose (S5 public API).

Deterministic via seeded SplitMix64 streams: same seed ⇒ bit-identical
keys across runs. ML-DSA-65 / ML-KEM-768 keys are REAL (pyca/cryptography via
pqblocks_jose.pq), held as FIPS seeds; classical components use the audited
``cryptography`` library. (Simulated until 2026-10-07.)
"""

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization

from pqblocks_jose.exceptions import PQBlocksJoseError

_MASK64 = 0xFFFFFFFFFFFFFFFF


from pqblocks_jose import pq  # noqa: E402


class _SplitMix64:
    """SplitMix64 DRBG (Steele et al.). Seeded named streams ."""

    def __init__(self, seed: int) -> None:
        self.state = int(seed) & _MASK64

    def next_u64(self) -> int:
        self.state = (self.state + 0x9E3779B97F4A7C15) & _MASK64
        z = self.state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & _MASK64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & _MASK64
        return (z ^ (z >> 31)) & _MASK64

    def next_bytes(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            out += self.next_u64().to_bytes(8, "little")
        return bytes(out[:n])


def _stream_bytes(seed: int, label: bytes, n: int) -> bytes:
    """Derive ``n`` deterministic bytes for a named stream."""
    # SHAKE256 over the WHOLE seed (review 2026-10-07): the former SplitMix64 path
    # masked every seed to 64 bits, capping every private key at 64 bits of entropy.
    seed = int(seed)
    seed_b = seed.to_bytes(max(1, (seed.bit_length() + 8) // 8), "big", signed=True)
    return hashlib.shake_256(b"pqblocks-jose-keypair-v2:" + label + b"|" + seed_b).digest(n)


@dataclass(frozen=True)
class KeyPair:
    """Hybrid key pair for a given algorithm.

    private_key/public_key are the concatenated (classical || PQ) materials,
    documented per algorithm:

    - ``"ML-DSA-65-Ed25519"``:
        private_key = ed25519_sk(32B) || ml_dsa_65_seed(32B, FIPS 204 xi)
        public_key  = ed25519_pk(32B) || ml_dsa_65_pk(1952B)
    - ``"X25519+MLKEM768"``:
        private_key = x25519_sk(32B) || ml_kem_768_seed(64B, FIPS 203 d||z)
        public_key  = x25519_pk(32B) || ml_kem_768_pk(1184B)
    """

    private_key: bytes
    public_key: bytes
    algorithm: str


# Layout constants (spec §1.2/§1.3)
_ED25519_LEN = 32
_MLDSA65_SK = 32      # seed (xi), the pyca/IETF private-key form
_MLDSA65_PK = 1952
_X25519_LEN = 32
_MLKEM768_SK = 64     # seed (d || z)
_MLKEM768_PK = 1184

JWS_ALG = "ML-DSA-65-Ed25519"
JWE_ALG = "X25519+MLKEM768"


class UnknownAlgorithmError(PQBlocksJoseError):
    """Raised when an unsupported algorithm identifier is passed in."""


def _ml_dsa_keypair(seed: int) -> tuple[bytes, bytes]:
    """Real ML-DSA-65 keypair (pyca/cryptography) from a seed-derived 32-byte xi.
    Replaces a simulated keypair of random-looking stream bytes (2026-10-07)."""
    return pq.mldsa65_keypair(_stream_bytes(seed, b"ml-dsa-65-keypair", _MLDSA65_SK))


def _ml_kem_keypair(seed: int) -> tuple[bytes, bytes]:
    """Real ML-KEM-768 keypair (pyca/cryptography) from a seed-derived d || z."""
    return pq.mlkem768_keypair(_stream_bytes(seed, b"ml-kem-768-keypair", _MLKEM768_SK))


def public_from_private(algorithm: str, private_key: bytes) -> bytes:
    """The public key belonging to a private key (both halves derived, never stored)."""
    if algorithm == JWS_ALG and len(private_key) == _ED25519_LEN + _MLDSA65_SK:
        ed_pk = ed25519.Ed25519PrivateKey.from_private_bytes(private_key[:32]).public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        return ed_pk + pq.mldsa65_keypair(private_key[32:])[0]
    if algorithm == JWE_ALG and len(private_key) == _X25519_LEN + _MLKEM768_SK:
        x_pk = x25519.X25519PrivateKey.from_private_bytes(private_key[:32]).public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        return x_pk + pq.mlkem768_keypair(private_key[32:])[0]
    raise UnknownAlgorithmError(f"cannot derive a public key for {algorithm!r} from {len(private_key)} bytes")


def generate_keypair(algorithm: str, seed: int | None = None) -> KeyPair:
    """Generate a deterministic hybrid key pair for ``algorithm``.

    Args:
        algorithm: ``"ML-DSA-65-Ed25519"`` or ``"X25519+MLKEM768"``.
        seed: SplitMix64 stream seed (for determinism).

    Returns:
        KeyPair with concatenated key materials.

    Raises:
        UnknownAlgorithmError: if algorithm is not one of the two supported.
        ValueError: if seed is not an int.
    """
    if not isinstance(algorithm, str):
        raise TypeError("algorithm must be a string")
    # This function held the last hardcoded credential default in the package
    # (the seed defaulted to a small constant).
    # generate_keypair is re-exported in __all__, so any caller - including a
    # downstream consumer of this library - who omitted seed= silently received
    # the SAME deterministic, publicly-known keypair every time, and its private
    # half is reproducible by anyone who reads this source. Every other function
    # here already fails closed on a missing credential; this one now does too.
    if seed is None:
        # production default: fresh randomness (review 2026-10-07 - an int seed
        # through SplitMix64 gives <= 64 bits of entropy; seeds are for tests only)
        seed = int.from_bytes(__import__("os").urandom(32), "big")    # 256 bits, kept whole by SHAKE256
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise ValueError("seed must be an int")

    if algorithm == JWS_ALG:
        ed_sk_bytes = _stream_bytes(seed, b"ed25519-keypair", 32)
        ed_sk = ed25519.Ed25519PrivateKey.from_private_bytes(ed_sk_bytes)
        ed_pk = ed_sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        ml_pk, ml_sk = _ml_dsa_keypair(seed)
        return KeyPair(
            private_key=ed_sk_bytes + ml_sk,
            public_key=ed_pk + ml_pk,
            algorithm=algorithm,
        )

    if algorithm == JWE_ALG:
        x_sk_bytes = _stream_bytes(seed, b"x25519-keypair", 32)
        x_sk = x25519.X25519PrivateKey.from_private_bytes(x_sk_bytes)
        x_pk = x_sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        mlk_pk, mlk_sk = _ml_kem_keypair(seed)
        return KeyPair(
            private_key=x_sk_bytes + mlk_sk,
            public_key=x_pk + mlk_pk,
            algorithm=algorithm,
        )

    raise UnknownAlgorithmError(
        f"Unsupported algorithm {algorithm!r}; expected {JWS_ALG!r} or {JWE_ALG!r}"
    )
