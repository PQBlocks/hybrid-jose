"""Versioned policy object for pqblocks-jose.

S4 contract: Policy Object Schema + Validation.

Provides:
- Policy dataclass with sane defaults
- PolicyValidator for schema validation
- Integration with JWS/JWE algorithms for policy-aware operations
"""

from dataclasses import dataclass, field
from typing import Optional


# Canonical values enforced by validators
CANONICAL_KDF = "HKDF-SHA256"
CANONICAL_KDF_INFO = "JOSE_PostQuantum_Traditional_Hybrid X25519MLKEM768"

# Supported policy versions (for migration support per EC7)
SUPPORTED_POLICY_VERSIONS = (1, 2)

# Default token size limit - accommodates ML-DSA-65-Ed25519 (~3.8KB)
DEFAULT_MAX_TOKEN_BYTES = 8192


@dataclass(frozen=True)
class Policy:
    """Versioned policy object binding algorithm choices and constraints.

    Per spec §1.4 and §2: all parameters are auto-derived from the policy;
    users never hand-tune algorithms. The policy object is the single
    source of truth.

    Fields:
        version: Policy version for forward compatibility (1 or 2).
        kem: Hybrid KEM identifier (e.g., "X25519+MLKEM768").
        sig: Hybrid signature identifier (e.g., "MLDSA65+Ed25519").
        kdf: Key derivation function (must be CANONICAL_KDF).
        kdf_info: HKDF info string (must be CANONICAL_KDF_INFO).
        sig_alg_std: Standards-track identifier per draft-ietf-jose-pq-composite-sigs.
        max_token_bytes: Max encoded JWS/JWE size (default: 8192).
        cnsA2_compliance: CNSA 2.0 conflict documentation.
    """
    version: int = 1
    kem: str = "X25519+MLKEM768"
    sig: str = "MLDSA65+Ed25519"
    kdf: str = CANONICAL_KDF
    kdf_info: str = CANONICAL_KDF_INFO
    sig_alg_std: str = "ML-DSA-65-Ed25519"
    max_token_bytes: int = DEFAULT_MAX_TOKEN_BYTES
    cnsA2_compliance: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize policy to dictionary."""
        from dataclasses import asdict
        return asdict(self)

    def to_json(self) -> str:
        """Serialize policy to JSON string."""
        import json
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict) -> 'Policy':
        """Deserialize policy from dictionary."""
        return cls(
            version=data.get('version', cls.version),
            kem=data.get('kem', cls.kem),
            sig=data.get('sig', cls.sig),
            kdf=data.get('kdf', cls.kdf),
            kdf_info=data.get('kdf_info', cls.kdf_info),
            sig_alg_std=data.get('sig_alg_std', cls.sig_alg_std),
            max_token_bytes=data.get('max_token_bytes', cls.max_token_bytes),
            cnsA2_compliance=data.get('cnsA2_compliance', {}),
        )

    @classmethod
    def from_json(cls, json_str: str) -> 'Policy':
        """Deserialize policy from JSON string."""
        import json
        data = json.loads(json_str)
        return cls.from_dict(data)


class PolicyValidator:
    """Validates policy objects against canonical constraints.

    Per spec §2: All parameters are auto-derived from the policy.
    Validators enforce canonical KDF, KDF info, and version values.
    """

    def validate(self, policy: Policy) -> bool:
        """Validate policy against canonical constraints.

        Returns:
            True if valid, raises PolicyMismatchError on violation.
        """
        if policy.kdf != CANONICAL_KDF:
            from pqblocks_jose.exceptions import PolicyMismatchError
            raise PolicyMismatchError(
                f"Unsupported kdf {policy.kdf!r}; expected {CANONICAL_KDF!r}"
            )
        if policy.kdf_info != CANONICAL_KDF_INFO:
            from pqblocks_jose.exceptions import PolicyMismatchError
            raise PolicyMismatchError(
                f"Policy kdf_info mismatch: {policy.kdf_info!r} != canonical"
            )
        if policy.version not in SUPPORTED_POLICY_VERSIONS:
            from pqblocks_jose.exceptions import PolicyMismatchError
            raise PolicyMismatchError(
                f"Unsupported policy version {policy.version!r}; "
                f"supported {list(SUPPORTED_POLICY_VERSIONS)}"
            )
        return True


# Module-level instance for convenience
_validator = PolicyValidator()


def validate_policy(policy: Policy) -> bool:
    """Convenience function to validate a policy object."""
    return _validator.validate(policy)
