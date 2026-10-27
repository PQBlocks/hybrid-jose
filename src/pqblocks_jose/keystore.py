"""Key Store: PEM/JWK Loading Helpers (S5.1).

Provides round-trip serialization of hybrid key pairs to/from:
- PEM text format (custom headers with algorithm identifier)
- JWK JSON format (file-based load/save)
"""

import base64
import json
import os
from dataclasses import dataclass
from typing import Optional, Union

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization

from pqblocks_jose.keypair import KeyPair, JWS_ALG, JWE_ALG
from pqblocks_jose.exceptions import KeyFormatError
from pqblocks_jose.keypair import _MLDSA65_SK as _DSA_SK, _MLKEM768_SK as _KEM_SK  # seed sizes


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    s = s + "=" * padding
    return base64.urlsafe_b64decode(s)


def _expand_ed25519_public_key(seed: bytes) -> bytes:
    ed_sk = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    return ed_sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _expand_x25519_public_key(seed: bytes) -> bytes:
    x_sk = x25519.X25519PrivateKey.from_private_bytes(seed)
    return x_sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _encode_pem(key_type: str, algorithm: str, material_b64: str) -> bytes:
    """Build a standard PEM block for hybrid key material."""
    header = f"Algorithm: {algorithm}\n"
    lines = [header]
    # Wrap base64 at 64 chars per PEM convention
    for i in range(0, len(material_b64), 64):
        lines.append(material_b64[i:i + 64])
    body = "\n".join(lines)
    if key_type == "private":
        return (
            f"-----BEGIN PQBLOCKS HYBRID PRIVATE KEY-----\n"
            f"{body}\n"
            "-----END PQBLOCKS HYBRID PRIVATE KEY-----\n"
        ).encode("utf-8")
    return (
        f"-----BEGIN PQBLOCKS HYBRID PUBLIC KEY-----\n"
        f"{body}\n"
        "-----END PQBLOCKS HYBRID PUBLIC KEY-----\n"
    ).encode("utf-8")


def _decode_pem(pem_bytes: bytes) -> tuple[str, bytes]:
    """Parse a standard PEM block, returning (algorithm, raw_material)."""
    text = pem_bytes.decode("utf-8", errors="strict")
    lines = text.splitlines()
    algorithm = None
    material_lines = []
    in_key = False
    for line in lines:
        line = line.strip()
        if line.startswith("-----BEGIN ") and ("PRIVATE KEY" in line or "PUBLIC KEY" in line):
            in_key = True
            continue
        if line.startswith("-----END ") and ("PRIVATE KEY" in line or "PUBLIC KEY" in line):
            break
        if in_key:
            if line.startswith("Algorithm:"):
                algorithm = line.split(":", 1)[1].strip()
            else:
                material_lines.append(line)
    if algorithm is None or not material_lines:
        raise KeyFormatError("PEM missing algorithm or key material")
    material_b64 = "".join(material_lines)
    try:
        raw = _b64url_decode(material_b64)
    except Exception:
        raise KeyFormatError("PEM key material is not valid base64url")
    return algorithm, raw


def load_private_key_from_pem(pem: bytes) -> KeyPair:
    """Load a full hybrid key pair from PEM bytes.

    Args:
        pem: PEM-encoded hybrid private key bytes.

    Returns:
        KeyPair with private_key and public_key populated.

    Raises:
        KeyFormatError: if pem is not bytes, is invalid PEM, or algorithm is unknown.
    """
    if not isinstance(pem, (bytes, bytearray)):
        raise KeyFormatError(f"pem must be bytes, got {type(pem).__name__}")
    algorithm, raw = _decode_pem(bytes(pem))
    if algorithm == JWS_ALG:
        # PEM for JWS private key: ed_sk(32) + ml_sk(_DSA_SK) + ed_pk(32) + ml_pk(1952) = (32 + _DSA_SK + 32 + 1952)
        if len(raw) != 32 + _DSA_SK + 32 + 1952:
            raise KeyFormatError(
                f"JWS key material length {len(raw)} does not match expected (32 + _DSA_SK + 32 + 1952)"
            )
        ed_sk = raw[0:32]
        ml_sk = raw[32:32 + _DSA_SK]
        ed_pk = raw[32 + _DSA_SK:32 + _DSA_SK + 32]
        ml_pk = raw[32 + _DSA_SK + 32:32 + _DSA_SK + 32 + 1952]
        return KeyPair(
            private_key=bytes(ed_sk) + bytes(ml_sk),
            public_key=bytes(ed_pk) + bytes(ml_pk),
            algorithm=algorithm,
        )
    if algorithm == JWE_ALG:
        # PEM for JWE private key: x_sk(32) + mlk_sk(_KEM_SK) + x_pk(32) + mlk_pk(1184) = (32 + _KEM_SK + 32 + 1184)
        if len(raw) != 32 + _KEM_SK + 32 + 1184:
            raise KeyFormatError(
                f"JWE key material length {len(raw)} does not match expected (32 + _KEM_SK + 32 + 1184)"
            )
        x_sk = raw[0:32]
        mlk_sk = raw[32:32 + _KEM_SK]
        x_pk = raw[32 + _KEM_SK:32 + _KEM_SK + 32]
        mlk_pk = raw[32 + _KEM_SK + 32:32 + _KEM_SK + 32 + 1184]
        return KeyPair(
            private_key=bytes(x_sk) + bytes(mlk_sk),
            public_key=bytes(x_pk) + bytes(mlk_pk),
            algorithm=algorithm,
        )
    raise KeyFormatError(f"Unsupported algorithm in PEM: {algorithm!r}")


def load_public_key_from_pem(pem: Union[bytes, bytearray]) -> KeyPair:
    """Load only the public portion from a PEM bytes.

    Args:
        pem: PEM-encoded hybrid public key bytes.

    Returns:
        KeyPair with public_key populated and private_key=None.

    Raises:
        KeyFormatError: if pem is not bytes, is invalid PEM, or algorithm is unknown.
    """
    if not isinstance(pem, (bytes, bytearray)):
        raise KeyFormatError(f"pem must be bytes, got {type(pem).__name__}")
    algorithm, raw = _decode_pem(bytes(pem))
    
    # Accept PEM that may contain private key material - extract just public part
    if algorithm == JWS_ALG:
        # Could be private key PEM ((32 + _DSA_SK + 32 + 1952) bytes) or public key PEM (1984 bytes)
        if len(raw) == 1984:
            # Public key only: ed_pk(32) + ml_pk(1952)
            ed_pk = raw[0:32]
            ml_pk = raw[32:32 + 1952]
            return KeyPair(
                private_key=None,
                public_key=bytes(ed_pk) + bytes(ml_pk),
                algorithm=algorithm,
            )
        elif len(raw) == (32 + _DSA_SK + 32 + 1952):
            # Private key PEM - extract public portion
            ed_pk = raw[32 + _DSA_SK:32 + _DSA_SK + 32]
            ml_pk = raw[32 + _DSA_SK + 32:32 + _DSA_SK + 32 + 1952]
            return KeyPair(
                private_key=None,
                public_key=bytes(ed_pk) + bytes(ml_pk),
                algorithm=algorithm,
            )
        else:
            raise KeyFormatError(
                f"JWS public key material length {len(raw)} unexpected"
            )
    
    if algorithm == JWE_ALG:
        # Could be private key PEM ((32 + _KEM_SK + 32 + 1184) bytes) or public key PEM (1216 bytes)
        if len(raw) == 1216:
            # Public key only: x_pk(32) + mlk_pk(1184)
            x_pk = raw[0:32]
            mlk_pk = raw[32:32 + 1184]
            return KeyPair(
                private_key=None,
                public_key=bytes(x_pk) + bytes(mlk_pk),
                algorithm=algorithm,
            )
        elif len(raw) == (32 + _KEM_SK + 32 + 1184):
            # Private key PEM - extract public portion
            x_pk = raw[32 + _KEM_SK:32 + _KEM_SK + 32]
            mlk_pk = raw[32 + _KEM_SK + 32:32 + _KEM_SK + 32 + 1184]
            return KeyPair(
                private_key=None,
                public_key=bytes(x_pk) + bytes(mlk_pk),
                algorithm=algorithm,
            )
        else:
            raise KeyFormatError(
                f"JWE public key material length {len(raw)} unexpected"
            )
    
    raise KeyFormatError(f"Unsupported algorithm in PEM: {algorithm!r}")


def load_jwk_from_file(path: str) -> KeyPair:
    """Load a hybrid key pair from a JWK JSON file.

    Args:
        path: Filesystem path to a JSON JWK file.

    Returns:
        KeyPair with key material populated from the JWK.

    Raises:
        KeyFormatError: if file is missing, invalid JSON, missing fields, or algorithm unknown.
    """
    if not isinstance(path, str):
        raise KeyFormatError(f"path must be a string, got {type(path).__name__}")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise KeyFormatError(f"JWK file not found: {path}")
    except json.JSONDecodeError as exc:
        raise KeyFormatError(f"JWK file contains invalid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise KeyFormatError("JWK must be a JSON object")
    # Check for kty field (spec compliance)
    if "kty" not in data:
        raise KeyFormatError("JWK missing required 'kty' field")
    # Also check algorithm field
    if "alg" not in data:
        raise KeyFormatError("JWK missing required 'alg' field")
    algorithm = data["alg"]
    has_private = "d" in data
    has_public = "n" in data
    if not has_public:
        raise KeyFormatError("JWK missing required 'n' (public key) field")

    try:
        public_raw = _b64url_decode(data["n"])
    except Exception as exc:
        raise KeyFormatError(f"JWK 'n' field is not valid base64url: {exc}") from exc

    if algorithm == JWS_ALG:
        # Public key: ed_pk(32) + ml_pk(1952) = 1984
        if len(public_raw) != 32 + 1952:
            raise KeyFormatError(
                f"JWK JWS public key length {len(public_raw)} does not match expected 1984"
            )
        if has_private:
            try:
                private_raw = _b64url_decode(data["d"])
            except Exception as exc:
                raise KeyFormatError(f"JWK 'd' field is not valid base64url: {exc}") from exc
            # Private key: ed_sk(32) + ml_sk(_DSA_SK) = 32 + _DSA_SK
            if len(private_raw) != 32 + _DSA_SK:
                raise KeyFormatError(
                    f"JWK JWS private key length {len(private_raw)} does not match expected 2592"
                )
            return KeyPair(
                private_key=private_raw,
                public_key=public_raw,
                algorithm=algorithm,
            )
        return KeyPair(
            private_key=None,
            public_key=public_raw,
            algorithm=algorithm,
        )

    if algorithm == JWE_ALG:
        # Public key: x_pk(32) + mlk_pk(1184) = 1216
        if len(public_raw) != 32 + 1184:
            raise KeyFormatError(
                f"JWK JWE public key length {len(public_raw)} does not match expected 1216"
            )
        if has_private:
            try:
                private_raw = _b64url_decode(data["d"])
            except Exception as exc:
                raise KeyFormatError(f"JWK 'd' field is not valid base64url: {exc}") from exc
            # Private key: x_sk(32) + mlk_sk(_KEM_SK) = 32 + _KEM_SK
            if len(private_raw) != 32 + _KEM_SK:
                raise KeyFormatError(
                    f"JWK JWE private key length {len(private_raw)} does not match expected 2432"
                )
            return KeyPair(
                private_key=private_raw,
                public_key=public_raw,
                algorithm=algorithm,
            )
        return KeyPair(
            private_key=None,
            public_key=public_raw,
            algorithm=algorithm,
        )

    raise KeyFormatError(f"Unsupported algorithm in JWK: {algorithm!r}")


def export_to_pem(keypair: KeyPair) -> bytes:
    """Export a hybrid key pair to PEM text format.

    Args:
        keypair: KeyPair to serialize.

    Returns:
        PEM-encoded bytes with algorithm header and base64url key material.

    Raises:
        TypeError: if keypair is not a KeyPair.
        ValueError: if algorithm is unsupported.
    """
    if not isinstance(keypair, KeyPair):
        raise TypeError(f"keypair must be a KeyPair, got {type(keypair).__name__}")
    if keypair.algorithm not in (JWS_ALG, JWE_ALG):
        raise ValueError(f"Unsupported algorithm for PEM export: {keypair.algorithm!r}")

    if keypair.private_key is not None:
        if keypair.algorithm == JWS_ALG:
            ed_sk_seed = keypair.private_key[0:32]
            ml_sk = keypair.private_key[32:32 + _DSA_SK]
            ed_pk = _expand_ed25519_public_key(ed_sk_seed)
            ml_pk = keypair.public_key[32:32 + 1952]
            material = ed_sk_seed + ml_sk + ed_pk + ml_pk
        elif keypair.algorithm == JWE_ALG:
            x_sk_seed = keypair.private_key[0:32]
            mlk_sk = keypair.private_key[32:32 + _KEM_SK]
            x_pk = _expand_x25519_public_key(x_sk_seed)
            mlk_pk = keypair.public_key[32:32 + 1184]
            material = x_sk_seed + mlk_sk + x_pk + mlk_pk
        else:
            raise ValueError(f"Unsupported algorithm for PEM export: {keypair.algorithm!r}")
        return _encode_pem("private", keypair.algorithm, _b64url_encode(material))

    material = keypair.public_key
    return _encode_pem("public", keypair.algorithm, _b64url_encode(material))


def export_to_jwk(keypair: KeyPair) -> dict:
    """Export a hybrid key pair to a JWK-like dict.

    Args:
        keypair: KeyPair to serialize.

    Returns:
        Dict with at least 'kty', 'alg', 'n' (public key base64url),
        and 'd' (private key base64url) when private_key is present.

    Raises:
        TypeError: if keypair is not a KeyPair.
        ValueError: if algorithm is unsupported.
    """
    if not isinstance(keypair, KeyPair):
        raise TypeError(f"keypair must be a KeyPair, got {type(keypair).__name__}")
    if keypair.algorithm not in (JWS_ALG, JWE_ALG):
        raise ValueError(f"Unsupported algorithm for JWK export: {keypair.algorithm!r}")

    jwk: dict = {
        "kty": "JOSE-Hybrid",
        "alg": keypair.algorithm,
        "n": _b64url_encode(keypair.public_key),
    }
    if keypair.private_key is not None:
        jwk["d"] = _b64url_encode(keypair.private_key)
    return jwk
