"""Exception classes for pqblocks-jose."""


class PQBlocksJoseError(Exception):
    """Base exception for all pqblocks-jose errors."""
    pass


class InvalidTokenError(PQBlocksJoseError):
    """Raised when token parsing fails: malformed header, invalid JSON, unsupported alg/enc."""
    pass


class TokenSizeExceededError(PQBlocksJoseError):
    """Raised when encoded token exceeds policy.max_token_bytes."""

    def __init__(self, actual: int, limit: int):
        super().__init__(f"Token size {actual} bytes exceeds limit {limit} bytes")
        self.actual = actual
        self.limit = limit


class DecryptionError(PQBlocksJoseError):
    """Raised when JWE decryption fails: invalid ciphertext, decapsulation failure, tag mismatch."""
    pass


class ReplayDetectedError(PQBlocksJoseError):
    """Raised when a token's jti is seen within the replay window."""

    def __init__(self, jti: str):
        super().__init__(f"Replay detected: jti={jti}")
        self.jti = jti


class PolicyMismatchError(PQBlocksJoseError):
    """Raised when token policy does not match verifier's expected policy (KDF, combiner, version)."""
    pass


class KeyFormatError(PQBlocksJoseError):
    """Raised when a key cannot be loaded from PEM/JWK (wrong format, missing fields, unsupported curve)."""
    pass