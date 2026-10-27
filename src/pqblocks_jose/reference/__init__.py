"""Reference module for pqblocks-jose.

Contains pure-Python reference implementations of hybrid JWS/JWE
algorithms serving as correctness oracles for optimized tiers.
"""

from pqblocks_jose.reference.jws import sign_jws, verify_jws, JWSResult, JsonStr

__all__ = [
    "sign_jws",
    "verify_jws",
    "JWSResult",
    "JsonStr",
]
